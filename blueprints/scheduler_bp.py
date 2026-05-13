"""
blueprints/scheduler_bp.py — Escaneos programados y gestión de BD
"""
from __future__ import annotations

import logging
import queue
import sqlite3
import threading
import time
import uuid
from datetime import datetime

from flask import Blueprint, jsonify, render_template, request

from db import get_scan_from_db
from scan_engine import _run_scan
from state import (
    API_KEY, DB_PATH, _db_write_lock, _jobs, _jobs_lock,
    rate_limit, require_api_key,
)

log = logging.getLogger("wpvulnscan.scheduler_bp")

scheduler_bp = Blueprint("scheduler", __name__)


@scheduler_bp.route("/schedules")
def schedules_page():
    return render_template("schedules.html", api_key=API_KEY)


@scheduler_bp.route("/api/db-status")
def db_status():
    from scheduler import get_scheduler_status
    from flask import current_app
    return jsonify(get_scheduler_status(current_app))


@scheduler_bp.route("/api/db-update/status")
def db_update_status():
    from scheduler import get_update_status
    return jsonify(get_update_status())


@scheduler_bp.route("/api/db-update", methods=["POST"])
@require_api_key
@rate_limit(3)
def db_update_now():
    source = request.get_json(silent=True) or {}
    src = source.get("source", "all")
    if src not in ["all", "nvd", "patchstack", "github", "wpscan", "wordfence", "offline"]:
        return jsonify({"error": "Fuente inválida"}), 400
    from scheduler import _run_update_thread, get_update_status
    if get_update_status().get("running"):
        return jsonify({"status": "already_running", "message": "Ya hay una actualización en curso"}), 409
    _run_update_thread(src)
    return jsonify({"status": "ok", "message": f"Actualización '{src}' iniciada en background"})


@scheduler_bp.route("/api/schedules", methods=["GET"])
@require_api_key
def list_schedules():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM scheduled_scans ORDER BY created_at DESC").fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@scheduler_bp.route("/api/schedules", methods=["POST"])
@require_api_key
@rate_limit(5)
def create_schedule():
    from state import normalize_url, is_safe_url
    data = request.get_json(silent=True) or {}
    url  = normalize_url((data.get("url") or "").strip())
    if not url:
        return jsonify({"error": "URL requerida"}), 400

    safe, reason = is_safe_url(url)
    if not safe:
        return jsonify({"error": f"URL no permitida: {reason}"}), 400

    cron_expr = data.get("cron_expr", "weekly")
    if cron_expr not in ("weekly", "daily", "monthly"):
        return jsonify({"error": "cron_expr debe ser: weekly, daily, monthly"}), 400

    sched_id = str(uuid.uuid4()).replace("-", "")[:12]
    with _db_write_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT INTO scheduled_scans
                (id, url, cron_expr, active, created_at, notify_email, callback_url)
            VALUES (?,?,?,1,?,?,?)
        """, (
            sched_id, url, cron_expr, datetime.now().isoformat(),
            data.get("notify_email", ""), data.get("callback_url", ""),
        ))
        conn.commit()
        conn.close()

    log.info("Escaneo programado creado: %s → %s (%s)", sched_id, url, cron_expr)
    return jsonify({"id": sched_id, "url": url, "cron_expr": cron_expr}), 201


@scheduler_bp.route("/api/schedules/<sched_id>", methods=["DELETE"])
@require_api_key
def delete_schedule(sched_id: str):
    with _db_write_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE scheduled_scans SET active=0 WHERE id=?", (sched_id,))
        conn.commit()
        conn.close()
    return jsonify({"status": "ok", "id": sched_id})


@scheduler_bp.route("/api/schedules/<sched_id>/run", methods=["POST"])
@require_api_key
@rate_limit(3)
def run_schedule_now(sched_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM scheduled_scans WHERE id=? AND active=1", (sched_id,)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({"error": "Schedule no encontrado o inactivo"}), 404

    url          = row["url"]
    callback_url = row["callback_url"] or ""

    job_id = str(uuid.uuid4()).replace("-", "")[:12]
    with _jobs_lock:
        _jobs[job_id] = {
            "status": "running", "url": url,
            "started": time.time(), "result": None,
            "queue": queue.Queue(),
        }
    threading.Thread(target=_run_scan, args=(job_id, url, True, "scheduler", callback_url), daemon=True).start()

    with _db_write_lock:
        c2 = sqlite3.connect(DB_PATH)
        c2.execute(
            "UPDATE scheduled_scans SET last_run=?, last_scan_id=? WHERE id=?",
            (datetime.now().isoformat(), job_id, sched_id)
        )
        c2.commit()
        c2.close()

    return jsonify({"job_id": job_id, "url": url})

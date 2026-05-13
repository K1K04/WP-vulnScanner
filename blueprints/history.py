"""
blueprints/history.py — Historial y comparativa
"""
from __future__ import annotations

import io
import logging
import sqlite3
from datetime import datetime

from flask import Blueprint, jsonify, render_template, request, send_file

from db import get_history, get_previous_scan_same_url, get_scan_from_db
from state import (
    API_KEY, DB_PATH, _int, _validate_job_id,
    rate_limit, require_api_key,
)

log = logging.getLogger("wpvulnscan.history")

history_bp = Blueprint("history", __name__)


@history_bp.route("/history")
def history_page():
    return render_template("index.html", api_key=API_KEY)


@history_bp.route("/api/history")
def history():
    limit      = _int(request.args.get("limit", 50), 50, 0, 200)
    offset     = _int(request.args.get("offset", 0), 0, 0, 100_000)
    risk_label = request.args.get("risk_label", "").strip()
    url_filter = request.args.get("url", "").strip()
    return jsonify(get_history(limit, offset, risk_label, url_filter))


@history_bp.route("/api/history/by-url")
def history_by_url():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "Parámetro url requerido"}), 400
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("""
            SELECT id, url, scanned_at, risk_score, risk_label, vuln_count,
                   critical_count, high_count, plugin_count, exposed_count
            FROM scans WHERE url LIKE ? ORDER BY scanned_at DESC LIMIT 20
        """, (f"%{url}%",)).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@history_bp.route("/api/history/auto-diff")
@rate_limit(20)
def history_auto_diff():
    """Compara un escaneo con el inmediatamente anterior del mismo dominio."""
    scan_id = (request.args.get("scan_id") or "").strip()
    if not scan_id:
        return jsonify({"error": "Parámetro scan_id requerido"}), 400
    if not _validate_job_id(scan_id):
        return jsonify({"error": "job_id inválido"}), 400

    current = get_scan_from_db(scan_id)
    if not current:
        return jsonify({"error": f"Escaneo {scan_id} no encontrado"}), 404
    current = dict(current)
    current.setdefault("scan_id", scan_id)

    previous = get_previous_scan_same_url(scan_id)
    if not previous:
        return jsonify({
            "has_previous": False,
            "scan_id": scan_id,
            "message": "No hay escaneo anterior para este dominio.",
        })

    from scanner.export import compare_scans

    diff = compare_scans(previous, current)
    progress = _build_progress_summary(diff, previous, current)
    return jsonify({
        "has_previous": True,
        "scan_id": scan_id,
        "previous_scan_id": previous.get("scan_id", ""),
        "previous_scanned_at": previous.get("scanned_at", ""),
        "diff": diff,
        "progress_summary": progress,
    })


@history_bp.route("/compare")
def compare_page():
    return render_template("compare.html", api_key=API_KEY)


@history_bp.route("/api/compare")
@require_api_key
def api_compare():
    id1 = request.args.get("id1")
    id2 = request.args.get("id2")
    if not id1 or not id2:
        return jsonify({"error": "Parámetros id1 e id2 requeridos"}), 400
    if not _validate_job_id(id1) or not _validate_job_id(id2):
        return jsonify({"error": "job_id inválido"}), 400

    r1 = get_scan_from_db(id1)
    r2 = get_scan_from_db(id2)
    if not r1:
        return jsonify({"error": f"Escaneo {id1} no encontrado"}), 404
    if not r2:
        return jsonify({"error": f"Escaneo {id2} no encontrado"}), 404

    from scanner.export import compare_scans
    return jsonify(compare_scans(r1, r2))


@history_bp.route("/api/compare/diff", methods=["GET"])
@require_api_key
def api_compare_diff():
    id1 = request.args.get("id1")
    id2 = request.args.get("id2")
    if not id1 or not id2:
        return jsonify({"error": "Parámetros id1 e id2 requeridos"}), 400
    if not _validate_job_id(id1) or not _validate_job_id(id2):
        return jsonify({"error": "job_id inválido"}), 400

    r1 = get_scan_from_db(id1)
    r2 = get_scan_from_db(id2)
    if not r1:
        return jsonify({"error": f"Escaneo {id1} no encontrado"}), 404
    if not r2:
        return jsonify({"error": f"Escaneo {id2} no encontrado"}), 404

    if r1.get("scanned_at", "") > r2.get("scanned_at", ""):
        r1, r2 = r2, r1

    from scanner.export import compare_scans
    diff = compare_scans(r1, r2)
    diff["progress_summary"] = _build_progress_summary(diff, r1, r2)
    return jsonify(diff)


@history_bp.route("/api/compare/progress-pdf", methods=["GET"])
@require_api_key
def api_compare_progress_pdf():
    id1 = request.args.get("id1")
    id2 = request.args.get("id2")
    if not id1 or not id2:
        return jsonify({"error": "Parámetros id1 e id2 requeridos"}), 400

    r1 = get_scan_from_db(id1)
    r2 = get_scan_from_db(id2)
    if not r1 or not r2:
        return jsonify({"error": "Uno o ambos escaneos no encontrados"}), 404

    if r1.get("scanned_at", "") > r2.get("scanned_at", ""):
        r1, r2 = r2, r1

    from scanner.export import compare_scans, generate_progress_pdf
    diff = compare_scans(r1, r2)
    diff["progress_summary"] = _build_progress_summary(diff, r1, r2)

    try:
        pdf_bytes = generate_progress_pdf(r1, r2, diff)
    except NotImplementedError:
        return jsonify({"error": "reportlab no instalado"}), 501
    except Exception as e:
        log.error("Progress PDF error: %s", e, exc_info=True)
        return jsonify({"error": "Error generando PDF"}), 500

    domain = r2.get("target_url", "site").split("//")[-1].split("/")[0]
    fname  = f"wpvuln-progress-{domain}.pdf"
    return send_file(io.BytesIO(pdf_bytes), mimetype="application/pdf",
                     as_attachment=True, download_name=fname)


                                                                                

def _build_progress_summary(diff: dict, scan_old: dict, scan_new: dict) -> dict:
    risk_old = diff.get("risk_old", 0)
    risk_new = diff.get("risk_new", 0)
    risk_pct = round(((risk_old - risk_new) / max(risk_old, 1)) * 100, 1) if risk_old > 0 else 0

    fixed  = len(diff.get("vulns_fixed", []))
    new_v  = len(diff.get("vulns_new", []))
    remain = len(diff.get("vulns_persist", []))

    if fixed > 0 and new_v == 0:       trend = "improving"
    elif new_v > fixed:                trend = "worsening"
    elif new_v == 0 and fixed == 0:    trend = "stable"
    else:                              trend = "mixed"

    critical_fixed = sum(1 for v in diff.get("vulns_fixed", [])
                         if isinstance(v, dict) and v.get("severity") == "critical")
    critical_new   = sum(1 for v in diff.get("vulns_new", [])
                         if isinstance(v, dict) and v.get("severity") == "critical")
    return {
        "trend":              trend,
        "risk_reduction_pct": max(0.0, risk_pct),
        "risk_increase_pct":  max(0.0, -risk_pct),
        "vulns_fixed":        fixed,
        "vulns_new":          new_v,
        "vulns_remaining":    remain,
        "critical_fixed":     critical_fixed,
        "critical_new":       critical_new,
        "plugins_updated":    len(diff.get("plugins_updated", [])),
        "files_fixed":        len(diff.get("files_fixed", [])),
        "headers_fixed":      len(diff.get("headers_fixed", [])),
        "days_between":       _days_between(scan_old.get("scanned_at", ""), scan_new.get("scanned_at", "")),
    }


def _days_between(date_str_a: str, date_str_b: str) -> int:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            a = datetime.strptime(date_str_a, fmt)
            b = datetime.strptime(date_str_b, fmt)
            return abs((b - a).days)
        except ValueError:
            continue
    return 0

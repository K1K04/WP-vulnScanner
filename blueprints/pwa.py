"""
blueprints/pwa.py — Push Notifications y caché offline
"""
from __future__ import annotations
import json, logging, os, sqlite3, uuid
from datetime import datetime
from flask import Blueprint, jsonify, request
from state import DB_PATH, _db_write_lock, rate_limit, require_api_key

log = logging.getLogger("wpvulnscan.pwa")
pwa_bp = Blueprint("pwa", __name__)


@pwa_bp.route("/api/pwa/subscribe", methods=["POST"])
@rate_limit(30)
def pwa_subscribe():
    data     = request.get_json(silent=True) or {}
    endpoint = (data.get("endpoint") or "").strip()
    keys     = data.get("keys") or {}
    p256dh   = (keys.get("p256dh") or "").strip()
    auth     = (keys.get("auth")   or "").strip()

    if not endpoint or not p256dh or not auth:
        return jsonify({"error": "endpoint, p256dh y auth son requeridos"}), 400
    if not endpoint.startswith("https://"):
        return jsonify({"error": "endpoint debe usar HTTPS"}), 400
    if len(endpoint) > 500 or len(p256dh) > 256 or len(auth) > 128:
        return jsonify({"error": "datos de suscripción inválidos"}), 400

    sub_id = str(uuid.uuid4()).replace("-", "")[:12]
    ua     = request.headers.get("User-Agent", "")[:200]
    try:
        with _db_write_lock:
            conn = sqlite3.connect(DB_PATH)
            conn.execute("""
                INSERT INTO push_subscriptions (id, endpoint, p256dh, auth, created_at, user_agent)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(endpoint) DO UPDATE SET p256dh=excluded.p256dh, auth=excluded.auth, active=1
            """, (sub_id, endpoint, p256dh, auth, datetime.now().isoformat(), ua))
            conn.commit()
            conn.close()
        return jsonify({"status": "ok", "id": sub_id})
    except Exception as e:
        log.error("pwa_subscribe error: %s", e)
        return jsonify({"error": "Error interno al registrar suscripción push"}), 500


@pwa_bp.route("/api/pwa/unsubscribe", methods=["POST"])
@rate_limit(30)
def pwa_unsubscribe():
    data     = request.get_json(silent=True) or {}
    endpoint = (data.get("endpoint") or "").strip()
    if not endpoint or not endpoint.startswith("https://") or len(endpoint) > 500:
        return jsonify({"error": "endpoint inválido"}), 400
    with _db_write_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE push_subscriptions SET active=0 WHERE endpoint=?", (endpoint,))
        conn.commit()
        conn.close()
    return jsonify({"status": "ok"})


@pwa_bp.route("/api/pwa/push-count", methods=["GET"])
def pwa_push_count():
    conn = sqlite3.connect(DB_PATH)
    try:
        count = conn.execute("SELECT COUNT(*) FROM push_subscriptions WHERE active=1").fetchone()[0]
        return jsonify({"active_subscriptions": count})
    finally:
        conn.close()


@pwa_bp.route("/api/pwa/notify", methods=["POST"])
@require_api_key
def pwa_notify():
    data  = request.get_json(silent=True) or {}
    title = data.get("title", "WP VulnScanner")
    body  = data.get("body",  "Nuevo resultado disponible")
    url   = data.get("url",   "/dashboard")

    vapid_private = os.environ.get("VAPID_PRIVATE_KEY", "")
    vapid_email   = os.environ.get("VAPID_EMAIL", "mailto:admin@example.com")

    if not vapid_private:
        return jsonify({
            "warning": "VAPID_PRIVATE_KEY no configurada.",
            "sent": 0,
        }), 202

    try:
        from pywebpush import webpush
    except ImportError:
        return jsonify({"error": "Instala pywebpush: pip install pywebpush"}), 501

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        subs = conn.execute(
            "SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE active=1"
        ).fetchall()
    finally:
        conn.close()

    payload = json.dumps({"title": title, "body": body, "url": url})
    sent = failed = 0
    for sub in subs:
        try:
            webpush(
                subscription_info={"endpoint": sub["endpoint"], "keys": {"p256dh": sub["p256dh"], "auth": sub["auth"]}},
                data=payload,
                vapid_private_key=vapid_private,
                vapid_claims={"sub": vapid_email},
            )
            sent += 1
        except Exception as push_err:
            log.warning("Push failed: %s", push_err)
            failed += 1

    return jsonify({"sent": sent, "failed": failed})


@pwa_bp.route("/api/pwa/last-result", methods=["GET"])
def pwa_last_result():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "url requerido"}), 400
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT result_json, cached_at, scan_id FROM pwa_cache WHERE url=?", (url,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"error": "Sin caché para esta URL"}), 404
    try:
        result = json.loads(row["result_json"])
        result["_cached"]    = True
        result["_cached_at"] = row["cached_at"]
        result["_scan_id"]   = row["scan_id"]
        return jsonify(result)
    except Exception as e:
        log.warning("pwa_last_result error: %s", e)
        return jsonify({"error": "Error obteniendo resultado en caché"}), 500


@pwa_bp.route("/api/pwa/vapid-public-key", methods=["GET"])
def pwa_vapid_public_key():
    key = os.environ.get("VAPID_PUBLIC_KEY", "")
    return jsonify({"vapid_public_key": key, "configured": bool(key)})

"""
blueprints/webhooks.py — Notificaciones vía Slack / Discord / Teams / genérico
===============================================================================
Permite configurar webhooks que se disparan automáticamente al terminar
un escaneo con severidad >= umbral configurado.

Rutas:
  GET  /api/webhooks              — lista webhooks configurados
  POST /api/webhooks              — crea webhook
  DELETE /api/webhooks/<id>       — elimina webhook
  POST /api/webhooks/<id>/test    — envía mensaje de prueba
  POST /api/webhooks/notify       — disparo manual (interno, usado por scan_engine)
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
import urllib.request as _ur
from datetime import datetime, timezone
from typing import Literal

from flask import Blueprint, jsonify, request

from state import DB_PATH, _db_write_lock, require_api_key, rate_limit, is_safe_url

log = logging.getLogger("wpvulnscan.webhooks")

webhooks_bp = Blueprint("webhooks", __name__)

WebhookType = Literal["slack", "discord", "teams", "generic"]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


                                                                                

def init_webhooks_table(conn: sqlite3.Connection):
    """Crea la tabla de webhooks si no existe."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS webhooks (
            id           TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            url          TEXT NOT NULL,
            type         TEXT NOT NULL DEFAULT 'generic',
            min_severity TEXT NOT NULL DEFAULT 'high',
            active       INTEGER DEFAULT 1,
            created_at   TEXT NOT NULL,
            last_fired   TEXT,
            fire_count   INTEGER DEFAULT 0,
            last_status  INTEGER,
            secret       TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_wh_active ON webhooks(active)")


def _get_all_webhooks(active_only: bool = True) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        if active_only:
            rows = conn.execute("SELECT * FROM webhooks WHERE active=1 ORDER BY created_at DESC").fetchall()
        else:
            rows = conn.execute("SELECT * FROM webhooks ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _mask_url(url: str) -> str:
    """Oculta el token del webhook en la URL para no exponerlo en la API."""
    parts = url.split("/")
    if len(parts) > 1:
        parts[-1] = parts[-1][:4] + "****" + parts[-1][-4:] if len(parts[-1]) > 8 else "****"
    return "/".join(parts)


                                                                                 

def _format_slack(result: dict, scan_id: str) -> dict:
    """Payload Slack Block Kit."""
    risk  = result.get("risk_score", 0)
    label = result.get("risk_label", "BAJO")
    url   = result.get("target_url", "")
    s     = result.get("summary", {})
    color = "#E53E3E" if risk >= 70 else "#DD6B20" if risk >= 45 else "#D69E2E" if risk >= 20 else "#38A169"

    vulns_crit = s.get("critical_vulns", 0)
    vulns_high = s.get("high_vulns", 0)

    text_lines = [f"*{url}*"]
    if vulns_crit:
        text_lines.append(f"🔴 {vulns_crit} vulnerabilidades CRÍTICAS")
    if vulns_high:
        text_lines.append(f"🟠 {vulns_high} vulnerabilidades ALTAS")

    return {
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🔍 WP VulnScanner — Escaneo completado", "emoji": True},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Sitio:*\n{url}"},
                        {"type": "mrkdwn", "text": f"*Riesgo:*\n`{label}` ({risk}/100)"},
                        {"type": "mrkdwn", "text": f"*Vulnerabilidades:*\n{s.get('vulns_found', 0)} ({vulns_crit} críticas, {vulns_high} altas)"},
                        {"type": "mrkdwn", "text": f"*Plugins detectados:*\n{s.get('plugins_found', 0)}"},
                    ],
                },
                {
                    "type": "actions",
                    "elements": [{
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Ver informe completo"},
                        "url":  f"/r/{scan_id}",
                        "style": "primary" if risk < 45 else "danger",
                    }],
                },
                {"type": "divider"},
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": f"Scan ID: `{scan_id}` · {result.get('scanned_at', '')}"}],
                },
            ],
        }],
    }


def _format_discord(result: dict, scan_id: str) -> dict:
    """Payload Discord Webhook."""
    risk  = result.get("risk_score", 0)
    label = result.get("risk_label", "BAJO")
    url   = result.get("target_url", "")
    s     = result.get("summary", {})
    color = 0xE53E3E if risk >= 70 else 0xDD6B20 if risk >= 45 else 0xD69E2E if risk >= 20 else 0x38A169

    fields = [
        {"name": "🎯 Sitio",              "value": f"`{url}`",                                     "inline": False},
        {"name": "⚡ Riesgo",             "value": f"**{label}** ({risk}/100)",                    "inline": True},
        {"name": "🐛 Vulnerabilidades",   "value": str(s.get("vulns_found", 0)),                   "inline": True},
        {"name": "🔴 Críticas",           "value": str(s.get("critical_vulns", 0)),                "inline": True},
        {"name": "🟠 Altas",             "value": str(s.get("high_vulns", 0)),                    "inline": True},
        {"name": "🔌 Plugins",           "value": str(s.get("plugins_found", 0)),                 "inline": True},
        {"name": "📂 Archivos expuestos", "value": str(s.get("exposed_files", 0)),                 "inline": True},
    ]

    if result.get("wp_outdated"):
        fields.append({"name": "⚠️ WordPress", "value": f"Desactualizado (v{result.get('wp_version', '?')})", "inline": False})

    return {
        "username": "WP VulnScanner",
        "avatar_url": "https://raw.githubusercontent.com/wpvulnscan/wpvulnscan-pro/main/static/pwa/icon-192.png",
        "embeds": [{
            "title":       "🔍 Escaneo de seguridad completado",
            "description": f"Resultado del análisis de **{url}**",
            "color":       color,
            "fields":      fields,
            "footer":      {"text": f"WP VulnScanner · Scan {scan_id}"},
            "timestamp":   datetime.now(timezone.utc).isoformat() + "Z",
        }],
    }


def _format_teams(result: dict, scan_id: str) -> dict:
    """Payload Microsoft Teams Adaptive Card."""
    risk  = result.get("risk_score", 0)
    label = result.get("risk_label", "BAJO")
    url   = result.get("target_url", "")
    s     = result.get("summary", {})
    color = "attention" if risk >= 70 else "warning" if risk >= 45 else "default"

    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type":    "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {"type": "TextBlock", "size": "Large", "weight": "Bolder",
                     "text": "🔍 WP VulnScanner — Escaneo completado"},
                    {"type": "TextBlock", "text": url, "wrap": True, "color": "accent"},
                    {"type": "FactSet", "facts": [
                        {"title": "Riesgo",              "value": f"{label} ({risk}/100)"},
                        {"title": "Vulnerabilidades",    "value": str(s.get("vulns_found", 0))},
                        {"title": "Críticas / Altas",    "value": f"{s.get('critical_vulns',0)} / {s.get('high_vulns',0)}"},
                        {"title": "Plugins",             "value": str(s.get("plugins_found", 0))},
                        {"title": "Archivos expuestos",  "value": str(s.get("exposed_files", 0))},
                        {"title": "Scan ID",             "value": scan_id},
                    ]},
                ],
                "actions": [{
                    "type":  "Action.OpenUrl",
                    "title": "Ver informe completo",
                    "url":   f"/r/{scan_id}",
                    "style": color,
                }],
            },
        }],
    }


def _format_generic(result: dict, scan_id: str) -> dict:
    """Payload JSON genérico (compatible con cualquier sistema)."""
    return {
        "event":      "scan_complete",
        "scan_id":    scan_id,
        "tool":       "WP VulnScanner",
        "timestamp":  datetime.now(timezone.utc).isoformat() + "Z",
        "target_url": result.get("target_url", ""),
        "risk": {
            "score": result.get("risk_score", 0),
            "label": result.get("risk_label", ""),
        },
        "summary":         result.get("summary", {}),
        "wp_version":      result.get("wp_version"),
        "wp_outdated":     result.get("wp_outdated", False),
        "xmlrpc_enabled":  result.get("xmlrpc_enabled", False),
        "waf_detected":    result.get("waf_detected", []),
        "vuln_count":      len(result.get("vulnerabilities", [])),
        "exposed_count":   len(result.get("exposed_files", [])),
        "report_url":      f"/r/{scan_id}",
    }


FORMATTERS = {
    "slack":   _format_slack,
    "discord": _format_discord,
    "teams":   _format_teams,
    "generic": _format_generic,
}


def _fire_one(webhook: dict, result: dict, scan_id: str) -> tuple[bool, int]:
    """Dispara un webhook individual. Devuelve (success, http_status)."""
    wtype   = webhook.get("type", "generic")
    wurl    = webhook.get("url", "")
    secret  = webhook.get("secret") or ""
    fmt     = FORMATTERS.get(wtype, _format_generic)

    try:
        payload = json.dumps(fmt(result, scan_id), ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "WPVulnScanner/6.1"}
        if secret:
            import hmac, hashlib
            sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
            headers["X-WPVulnScanner-Signature"] = f"sha256={sig}"

        req = _ur.Request(wurl, data=payload, headers=headers, method="POST")
        with _ur.urlopen(req, timeout=10) as resp:
            status = resp.status
        return True, status
    except Exception as e:
        log.warning("Webhook %s falló: %s", webhook.get("id"), e)
        return False, 0


def _should_fire(webhook: dict, result: dict) -> bool:
    """Comprueba si el escaneo supera el umbral de severidad del webhook."""
    min_sev = webhook.get("min_severity", "high")
    threshold = SEVERITY_ORDER.get(min_sev, 1)
    s = result.get("summary", {})
    counts = {
        "critical": s.get("critical_vulns", 0),
        "high":     s.get("high_vulns", 0),
        "medium":   s.get("vulns_found", 0) - s.get("high_vulns", 0) - s.get("critical_vulns", 0),
    }
    for sev, count in counts.items():
        if count > 0 and SEVERITY_ORDER.get(sev, 99) <= threshold:
            return True
    return result.get("risk_score", 0) >= 45


def fire_webhooks(result: dict, scan_id: str):
    """Dispara todos los webhooks activos que cumplan el umbral. Llamado desde scan_engine."""
    webhooks = _get_all_webhooks(active_only=True)
    if not webhooks:
        return
    now = datetime.now(timezone.utc).isoformat() + "Z"
    for wh in webhooks:
        if not _should_fire(wh, result):
            continue
        success, status = _fire_one(wh, result, scan_id)
        try:
            with _db_write_lock:
                conn = sqlite3.connect(DB_PATH)
                conn.execute("""
                    UPDATE webhooks SET last_fired=?, fire_count=fire_count+1, last_status=? WHERE id=?
                """, (now, status, wh["id"]))
                conn.commit()
                conn.close()
        except Exception as e:
            log.warning("No se pudo actualizar estado del webhook: %s", e)
        log.info("Webhook '%s' (%s) → %s [HTTP %s]", wh.get("name"), wh.get("type"),
                 "OK" if success else "FAIL", status)


                                                                                

@webhooks_bp.route("/api/webhooks", methods=["GET"])
@require_api_key
def list_webhooks():
    rows = _get_all_webhooks(active_only=False)
                                        
    for r in rows:
        r["url"] = _mask_url(r["url"])
    return jsonify(rows)


@webhooks_bp.route("/api/webhooks", methods=["POST"])
@require_api_key
@rate_limit(10)
def create_webhook():
    data     = request.get_json(silent=True) or {}
    name     = (data.get("name") or "").strip()
    url      = (data.get("url")  or "").strip()
    wtype    = data.get("type", "generic")
    min_sev  = data.get("min_severity", "high")
    secret   = (data.get("secret") or "").strip()

    if not name or not url:
        return jsonify({"error": "name y url son requeridos"}), 400
    if wtype not in ("slack", "discord", "teams", "generic"):
        return jsonify({"error": "type debe ser: slack, discord, teams, generic"}), 400
    if min_sev not in ("critical", "high", "medium", "low"):
        return jsonify({"error": "min_severity debe ser: critical, high, medium, low"}), 400

    safe, reason = is_safe_url(url)
    if not safe:
        return jsonify({"error": f"URL del webhook no permitida: {reason}"}), 400

    wh_id = str(uuid.uuid4()).replace("-", "")[:12]
    try:
        with _db_write_lock:
            conn = sqlite3.connect(DB_PATH)
            conn.execute("""
                INSERT INTO webhooks (id, name, url, type, min_severity, active, created_at, secret)
                VALUES (?,?,?,?,?,1,?,?)
            """, (wh_id, name, url, wtype, min_sev, datetime.now(timezone.utc).isoformat(), secret or None))
            conn.commit()
            conn.close()
        log.info("Webhook creado: %s [%s] → %s", name, wtype, _mask_url(url))
        return jsonify({"id": wh_id, "name": name, "type": wtype, "min_severity": min_sev}), 201
    except Exception as e:
        log.error("Error creando webhook: %s", e)
        return jsonify({"error": "Error interno al crear el webhook"}), 500


@webhooks_bp.route("/api/webhooks/<wh_id>", methods=["DELETE"])
@require_api_key
def delete_webhook(wh_id: str):
    with _db_write_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE webhooks SET active=0 WHERE id=?", (wh_id,))
        conn.commit()
        conn.close()
    return jsonify({"status": "ok", "id": wh_id})


@webhooks_bp.route("/api/webhooks/<wh_id>/test", methods=["POST"])
@require_api_key
@rate_limit(5)
def test_webhook(wh_id: str):
    """Envía un payload de prueba al webhook."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM webhooks WHERE id=? AND active=1", (wh_id,)).fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({"error": "Webhook no encontrado"}), 404

                                  
    test_result = {
        "target_url":  "https://ejemplo-wordpress.com",
        "risk_score":  75,
        "risk_label":  "CRÍTICO",
        "wp_version":  "6.4.2",
        "wp_outdated": True,
        "xmlrpc_enabled": True,
        "waf_detected": [],
        "scanned_at":  datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "vulns_found":    8,
            "critical_vulns": 2,
            "high_vulns":     3,
            "plugins_found":  12,
            "exposed_files":  2,
        },
        "vulnerabilities": [],
    }

    wh       = dict(row)
    success, status = _fire_one(wh, test_result, "test-000000")
    return jsonify({
        "ok":      success,
        "status":  status,
        "webhook": {"id": wh_id, "name": wh.get("name"), "type": wh.get("type")},
    })


@webhooks_bp.route("/api/webhooks/types")
def webhook_types():
    """Documentación de los tipos de webhook disponibles."""
    return jsonify({
        "types": {
            "slack":   {"name": "Slack",           "description": "Block Kit message con colores según severidad"},
            "discord": {"name": "Discord",          "description": "Embed con campos de resumen y color por riesgo"},
            "teams":   {"name": "Microsoft Teams",  "description": "Adaptive Card compatible con Teams y Outlook"},
            "generic": {"name": "Generic JSON",     "description": "JSON estándar para cualquier sistema"},
        },
        "severities": ["critical", "high", "medium", "low"],
        "signature":  "HMAC-SHA256 en header X-WPVulnScanner-Signature (si se configura secret)",
    })

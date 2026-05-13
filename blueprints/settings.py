"""
blueprints/settings.py — Gestión de claves API
"""
from __future__ import annotations
import logging, os
from flask import Blueprint, jsonify, render_template, request
from state import API_KEY, DB_PATH, rate_limit, require_api_key

log = logging.getLogger("wpvulnscan.settings")
settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/settings")
def settings_page():
    return render_template("settings.html", api_key=API_KEY)


@settings_bp.route("/api/settings/keys", methods=["GET"])
@require_api_key
def settings_keys_get():
    from scanner.api_keys import get_api_keys, get_services_catalog, SERVICES, mask_value
    keys = get_api_keys(DB_PATH)
                                                                
    for k in keys:
        k["source"] = "db"

    by_service = {k.get("service"): k for k in keys}
    catalog = get_services_catalog()
    env_status = {}
    extra_vars = [
        "SECRET_KEY", "API_KEY", "GITHUB_TOKEN", "SMTP_HOST",
        "VAPID_PUBLIC_KEY", "GEMINI_API_KEY", "ANTHROPIC_API_KEY",
        "AI_PROVIDER", "GEMINI_MODEL", "CLAUDE_MODEL", "OLLAMA_BASE_URL", "OLLAMA_MODEL",
        "OLLAMA_MODEL_FALLBACKS",
        "GEMINI_TIMEOUT_SECONDS", "GEMINI_STREAM_TIMEOUT_SECONDS",
        "CLAUDE_TIMEOUT_SECONDS", "CLAUDE_STREAM_TIMEOUT_SECONDS",
        "OLLAMA_TIMEOUT_SECONDS", "OLLAMA_STREAM_TIMEOUT_SECONDS",
        "OLLAMA_PLAN_TIMEOUT_SECONDS", "OLLAMA_TAGS_TIMEOUT_SECONDS",
        "AI_PLAN_MAX_TOKENS", "AI_PLAN_RETRY_MAX_TOKENS",
        "OLLAMA_PLAN_RETRY_TIMEOUT_SECONDS",
        "UI_BASIC_AUTH_USER", "UI_BASIC_AUTH_PASS",
    ]
    for svc_id, meta in SERVICES.items():
        ev = meta.get("env_var")
        if ev:
            env_status[ev] = bool(os.environ.get(ev, "").strip())
                                                                             
            if env_status[ev] and svc_id not in by_service:
                plain = os.environ.get(ev, "").strip()
                keys.append({
                    "id": f"env-{svc_id.lower()}",
                    "service": svc_id,
                    "label": meta.get("label", svc_id),
                    "description": meta.get("description", ""),
                    "priority": meta.get("priority", "optional"),
                    "env_var": ev,
                    "docs_url": meta.get("docs_url"),
                    "icon": meta.get("icon", "key"),
                    "value_mask": mask_value(plain) if plain else "****",
                    "created_at": None,
                    "last_used": None,
                    "last_tested": None,
                    "test_ok": None,
                    "active": True,
                    "source": "env",
                })
    for ev in extra_vars:
        if ev not in env_status:
            env_status[ev] = bool(os.environ.get(ev, "").strip())
    return jsonify({"keys": keys, "catalog": catalog, "env_status": env_status})


@settings_bp.route("/api/settings/keys", methods=["POST"])
@require_api_key
def settings_keys_post():
    from scanner.api_keys import upsert_api_key
    data    = request.get_json(silent=True) or {}
    service = (data.get("service") or "").strip()
    value   = (data.get("value")   or "").strip()
    if not service or not value:
        return jsonify({"error": "service y value son requeridos"}), 400
    try:
        result = upsert_api_key(DB_PATH, service, value)
        log.info("API key saved for service=%s from IP=%s", service, request.remote_addr)
        return jsonify({"status": "ok", "key": result})
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        log.error("Error saving API key: %s", e)
        return jsonify({"error": "Error interno al guardar la clave"}), 500


@settings_bp.route("/api/settings/keys/<service>", methods=["DELETE"])
@require_api_key
def settings_keys_delete(service: str):
    from scanner.api_keys import delete_api_key
    deleted = delete_api_key(DB_PATH, service)
    if not deleted:
        return jsonify({"error": "Clave no encontrada"}), 404
    log.info("API key deleted for service=%s from IP=%s", service, request.remote_addr)
    return jsonify({"status": "ok"})


@settings_bp.route("/api/settings/keys/test/<service>", methods=["POST"])
@require_api_key
@rate_limit(5)
def settings_keys_test(service: str):
    from scanner.api_keys import test_api_key
    try:
        result = test_api_key(DB_PATH, service)
        return jsonify(result)
    except Exception as e:
        log.error("Key test error for %s: %s", service, e)
        return jsonify({"ok": False, "error": "Error al probar la clave API"}), 500

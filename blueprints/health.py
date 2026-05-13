"""
blueprints/health.py — Health checks y versión
"""
from __future__ import annotations
import logging, sqlite3, time
from datetime import datetime
from flask import Blueprint, jsonify
from db import _db
from state import (
    APP_VERSION, APP_START, API_KEY, VERIFY_SSL,
    MAX_CONCURRENT, SCAN_TIMEOUT_S,
    _active_scans_count, _active_scans_lock, _jobs, _jobs_lock, DB_PATH,
)

log = logging.getLogger("wpvulnscan.health")
health_bp = Blueprint("health", __name__)


@health_bp.route("/health")
@health_bp.route("/api/health")
def health():
    health_status = {"status": "ok", "version": APP_VERSION, "uptime": round(time.time() - APP_START), "checks": {}}
    
    # 1️⃣ Verificar BD principal
    try:
        with _db() as conn:
            result = conn.execute("SELECT COUNT(*) FROM scans").fetchone()
            health_status["checks"]["scans_db"] = {"ok": True, "count": result[0] if result else 0}
    except Exception as e:
        log.warning("Health check — BD principal error: %s", e)
        health_status["status"] = "unhealthy"
        health_status["checks"]["scans_db"] = {"ok": False, "error": str(e)[:80]}
    
    # 2️⃣ Verificar BD de vulnerabilidades
    try:
        from scanner.vulns_db import get_db_stats
        stats = get_db_stats()
        health_status["checks"]["vulns_db"] = {"ok": True, "total_vulns": stats.get("total_vulns", 0)}
    except Exception as e:
        log.debug("Health check — BD vulns: %s", e)
        health_status["checks"]["vulns_db"] = {"ok": False, "error": str(e)[:80]}
    
    # 3️⃣ Verificar espacio en disco
    try:
        import shutil
        stat = shutil.disk_usage(DB_PATH)
        free_mb = stat.free / (1024 * 1024)
        if free_mb < 50:
            log.warning("⚠️ Espacio en disco bajo: %.1f MB", free_mb)
            health_status["status"] = "degraded"
            health_status["checks"]["disk"] = {"ok": False, "free_mb": round(free_mb, 1), "warning": "low_space"}
        else:
            health_status["checks"]["disk"] = {"ok": True, "free_mb": round(free_mb, 1)}
    except Exception as e:
        health_status["checks"]["disk"] = {"ok": False, "error": str(e)[:80]}
    
    return jsonify(health_status), (200 if health_status["status"] == "ok" else (503 if health_status["status"] == "unhealthy" else 200))


@health_bp.route("/api/version")
def api_version():
    from state import SCAN_RATE_LIMIT
    return jsonify({
        "version":        APP_VERSION,
        "api_key_set":    bool(API_KEY),
        "verify_ssl":     VERIFY_SSL,
        "max_concurrent": MAX_CONCURRENT,
        "scan_timeout":   SCAN_TIMEOUT_S,
    })


@health_bp.route("/api/health/deep")
def health_deep():
    checks      = {}
    status_code = 200

    try:
        conn = sqlite3.connect(DB_PATH, timeout=2)
        conn.execute("SELECT COUNT(*) FROM scans").fetchone()
        conn.close()
        checks["scans_db"] = "ok"
    except Exception as e:
        checks["scans_db"] = f"error: {e}"
        status_code = 503

    try:
        from scanner.vulns_db import get_db_stats, get_db_freshness
        stats     = get_db_stats()
        freshness = get_db_freshness()
        checks["vulns_db"] = {
            "status":      "ok",
            "total_vulns": stats["total_vulns"],
            "fresh":       freshness["fresh"],
            "days_old":    freshness["days_old"],
        }
    except Exception as e:
        checks["vulns_db"] = f"error: {e}"
        status_code = 503

    with _active_scans_lock:
        slots = MAX_CONCURRENT - _active_scans_count
    checks["concurrency"] = {"slots_free": slots, "slots_max": MAX_CONCURRENT, "saturated": slots == 0}
    if slots == 0:
        status_code = max(status_code, 429)

    with _jobs_lock:
        running = sum(1 for j in _jobs.values() if j.get("status") == "running")
    checks["jobs_running"] = running

    from flask import current_app
    scheduler = current_app.config.get("SCHEDULER")
    checks["scheduler"] = "apscheduler" if scheduler else "simple-timer"

    return jsonify({
        "status":    "ok" if status_code == 200 else "degraded",
        "timestamp": datetime.now().isoformat(),
        "checks":    checks,
    }), status_code


@health_bp.route("/api/cache/stats")
def cache_stats():
    """Estadísticas del cache de resultados en memoria."""
    try:
        from state import _scan_cache, _scan_cache_lock, SCAN_CACHE_TTL
        import time
        now = time.time()
        with _scan_cache_lock:
            total   = len(_scan_cache)
            fresh   = sum(1 for v in _scan_cache.values() if now - v["ts"] < SCAN_CACHE_TTL)
            expired = total - fresh
            entries = [
                {
                    "url":     v["data"].get("target_url", "?"),
                    "age_s":   int(now - v["ts"]),
                    "fresh":   (now - v["ts"]) < SCAN_CACHE_TTL,
                    "risk":    v["data"].get("risk_score", 0),
                }
                for v in _scan_cache.values()
            ]
        return jsonify({
            "ttl_s":   SCAN_CACHE_TTL,
            "total":   total,
            "fresh":   fresh,
            "expired": expired,
            "entries": sorted(entries, key=lambda x: x["age_s"]),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

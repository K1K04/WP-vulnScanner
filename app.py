"""
WP VulnScanner — Flask app v6.1
=====================================
app.py ahora es solo el punto de entrada y registro de blueprints.
Toda la lógica de negocio vive en:
  state.py          — configuración y helpers compartidos
  db.py             — capa de acceso a datos
  scan_engine.py    — motor de escaneo asíncrono
  pdf_gen.py        — generación de PDF técnico
  blueprints/
    scan.py         — /scan, /api/scan, /api/bulk, /r/<id>, ...
    history.py      — /history, /api/history, /api/compare, ...
    dashboard.py    — /dashboard, /api/dashboard, ...
    scheduler_bp.py — /schedules, /api/schedules, /api/db-update, ...
    settings.py     — /settings, /api/settings/keys, ...
    vulns.py        — /vulns-db, /api/vulns, ...
    health.py       — /health, /api/health, /api/version, ...
    pwa.py          — /api/pwa/*, ...
    ai.py           — /api/ai-plan, /api/ai-chat
"""

import logging
import os
import secrets
import threading
import base64
import hmac as _hmac
import binascii as _binascii

try:
    from dotenv import load_dotenv as _load_dotenv
except ImportError:
    _load_dotenv = None
from flask import Flask, render_template, jsonify
from flask import Response
from flask import request as _req
from flask_compress import Compress

                                                                                
if _load_dotenv:
    _load_dotenv()

                                                                                
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("wpvulnscan")

if _load_dotenv is None:
    log.warning("python-dotenv no instalado — se omite carga automática de .env")

                                                                                
import state              

                                                                                
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Comprimir respuestas JSON
Compress(app)
app.config['COMPRESS_MIN_SIZE'] = 500  # Solo comprimir > 500 bytes

                         
try:
    from flask_compress import Compress as _Compress
    _Compress(app)
    log.info("flask-compress activo")
except ImportError:
    pass

                                                                                
if not os.environ.get("SECRET_KEY"):
    log.warning("SECRET_KEY no definida — usando clave temporal. Define una en producción.")

_sk = os.environ.get("SECRET_KEY", "")
_ak = os.environ.get("API_KEY", "")
if _sk and _ak and _sk == _ak:
    log.warning("⚠️  SECRET_KEY y API_KEY son iguales — riesgo de seguridad.")

if not state.VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    log.warning("VERIFY_SSL=false — verificación desactivada (solo lab)")


_UI_BASIC_USER = os.environ.get("UI_BASIC_AUTH_USER", "").strip()
_UI_BASIC_PASS = os.environ.get("UI_BASIC_AUTH_PASS", "").strip()
_BOOTSTRAP_RUNTIME_DONE = False
_BOOTSTRAP_RUNTIME_LOCK = threading.Lock()
_BOOT_RECOVERY_DONE = False
_BOOT_RECOVERY_LOCK = threading.Lock()


def _ensure_runtime_bootstrap() -> None:
    """Inicializa DB principal y vulns.db en cualquier modo de arranque."""
    global _BOOTSTRAP_RUNTIME_DONE
    if _BOOTSTRAP_RUNTIME_DONE:
        return
    with _BOOTSTRAP_RUNTIME_LOCK:
        if _BOOTSTRAP_RUNTIME_DONE:
            return
        from db import init_db
        from scanner.vulns_db import init_vulns_db

        init_db()
        init_vulns_db()
        _BOOTSTRAP_RUNTIME_DONE = True


                                                                     
_ensure_runtime_bootstrap()


def _ensure_boot_recovery() -> None:
    """Ejecuta una vez la recuperación de jobs interrumpidos tras reinicio."""
    global _BOOT_RECOVERY_DONE
    if _BOOT_RECOVERY_DONE:
        return
    with _BOOT_RECOVERY_LOCK:
        if _BOOT_RECOVERY_DONE:
            return
        try:
            from scan_engine import recover_interrupted_jobs_on_startup

            recovered = int(recover_interrupted_jobs_on_startup() or 0)
            if recovered > 0:
                log.warning("Recuperación de arranque: %d job(s) rehidratados en memoria", recovered)
        except Exception as exc:
            log.warning("No se pudo ejecutar recuperación de arranque: %s", exc)
        finally:
            _BOOT_RECOVERY_DONE = True


def _ui_basic_enabled() -> bool:
    return bool(_UI_BASIC_USER and _UI_BASIC_PASS)


def _should_protect_ui(path: str) -> bool:
                                                                            
    if path.startswith("/api/"):
        return False
    if path == "/health":
        return False
                                                                                 
                                                                                
    if path.startswith("/static/"):
        return False
    return True


def _parse_basic_auth(auth_header: str) -> tuple[str, str]:
    if not auth_header or not auth_header.lower().startswith("basic "):
        return "", ""
    token = auth_header.split(" ", 1)[1].strip()
    try:
        decoded = base64.b64decode(token).decode("utf-8")
    except (_binascii.Error, UnicodeDecodeError, ValueError):
        return "", ""
    user, sep, pwd = decoded.partition(":")
    if not sep:
        return "", ""
    return user, pwd


@app.before_request
def require_ui_basic_auth():
    _ensure_boot_recovery()

    if not _ui_basic_enabled():
        return None

    path = _req.path or "/"
    if not _should_protect_ui(path):
        return None

    user, pwd = _parse_basic_auth(_req.headers.get("Authorization", ""))
    if _hmac.compare_digest(user, _UI_BASIC_USER) and _hmac.compare_digest(pwd, _UI_BASIC_PASS):
        return None

    return Response(
        "Autenticación requerida",
        401,
        {"WWW-Authenticate": 'Basic realm="WP VulnScanner UI"'},
    )

                                                                                
@app.after_request
def add_security_headers(response):
    import secrets as _sec
    is_attack_map = _req.endpoint == "scan.attack_map"

                                    
    req_id = _req.headers.get("X-Request-ID") or _sec.token_hex(8)
    response.headers["X-Request-ID"] = req_id

    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN" if is_attack_map else "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("X-XSS-Protection", "1; mode=block")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")
    response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
    frame_ancestors = "'self'" if is_attack_map else "'none'"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' fonts.googleapis.com fonts.gstatic.com; "
        "font-src 'self' fonts.gstatic.com data:; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "worker-src 'self'; "
        "manifest-src 'self'; "
        f"frame-ancestors {frame_ancestors};"
    )
    response.headers.setdefault("X-Robots-Tag", "noindex, nofollow")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    return response


                                                                                 
@app.errorhandler(404)
def not_found(e):
    from flask import request as _r
    if _r.path.startswith("/api/") or _r.path.startswith("/scan"):
        return jsonify({"error": "Ruta no encontrada", "path": _r.path}), 404
    return render_template("index.html", api_key=state.API_KEY), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Método no permitido"}), 405

@app.errorhandler(500)
def internal_error(e):
    log.error("Error interno: %s", e, exc_info=True)
    if _req.path.startswith("/api/") or _req.path.startswith("/scan"):
        return jsonify({"error": "Error interno del servidor"}), 500
    return render_template("index.html", api_key=state.API_KEY), 500


                                                                                 
@app.route("/")
def index():
    return render_template("index.html", api_key=state.API_KEY)


                                                                                 
from blueprints.scan         import scan_bp
from blueprints.history      import history_bp
from blueprints.dashboard    import dashboard_bp
from blueprints.scheduler_bp import scheduler_bp
from blueprints.settings     import settings_bp
from blueprints.vulns        import vulns_bp
from blueprints.health       import health_bp
from blueprints.pwa          import pwa_bp
from blueprints.ai           import ai_bp
from blueprints.sarif        import sarif_bp
from blueprints.webhooks     import webhooks_bp
from blueprints.stats        import stats_bp

app.register_blueprint(scan_bp)
app.register_blueprint(history_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(scheduler_bp)
app.register_blueprint(settings_bp)
app.register_blueprint(vulns_bp)
app.register_blueprint(health_bp)
app.register_blueprint(pwa_bp)
app.register_blueprint(ai_bp)
app.register_blueprint(sarif_bp)
app.register_blueprint(webhooks_bp)
app.register_blueprint(stats_bp)


                                                                                 
if __name__ == "__main__":
    import logging.handlers as _lh

    log_file = os.environ.get("LOG_FILE", "")
    if log_file:
        _fh = _lh.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        _fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        logging.getLogger().addHandler(_fh)

    from db import _start_cleanup_timer
    from scheduler import start_scheduler

    _ensure_runtime_bootstrap()
    _ensure_boot_recovery()
    start_scheduler(app)
    _start_cleanup_timer()

    port  = state._env_int("PORT", 5000, min_val=1, max_val=65535)
    debug = os.environ.get("DEBUG", "False").lower() == "true"

                                                                              

    app.run(debug=debug, host="0.0.0.0", port=port, threaded=True)

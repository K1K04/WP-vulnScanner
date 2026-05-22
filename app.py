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
try:
    from flask_compress import Compress as _RealCompress
    Compress = _RealCompress
    _FLASK_COMPRESS_AVAILABLE = True
except ImportError:
    _FLASK_COMPRESS_AVAILABLE = False
    class _CompressFallback:  # Graceful no-op fallback
        def __init__(self, app=None):
            if app:
                self.init_app(app)
        def init_app(self, app):
            pass
    Compress = _CompressFallback

try:
    from flask_restx import Api, Resource, Namespace, fields as restx_fields  # type: ignore[import-not-found]
    FLASK_RESTX_AVAILABLE = True
except ImportError:
    Api = None
    Resource = None
    Namespace = None
    restx_fields = None
    FLASK_RESTX_AVAILABLE = False

                                                                                
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
if _FLASK_COMPRESS_AVAILABLE:
    app.config['COMPRESS_MIN_SIZE'] = 500  # Solo comprimir > 500 bytes
    log.info("flask-compress activo")
else:
    log.warning("flask-compress no disponible — respuestas sin compresión gzip")

# ──── Flask-RESTX Setup ────────────────────────────────────────────────────────
if FLASK_RESTX_AVAILABLE and Api is not None:
    app.config['RESTX_MASK_SWAGGER'] = False  # Disable field masking
    api = Api(
        app,
        version='6.1',
        title='WP VulnScanner Pro API',
        description='API para análisis de vulnerabilidades en WordPress',
        doc='/docs',  # Swagger UI endpoint
        prefix='/api/v1',
    )
    log.info("Flask-RESTX initialized — OpenAPI docs available at /api/v1/docs")
else:
    api = None
    log.warning("Flask-RESTX no disponible — endpoints sin documentación OpenAPI")

                                                                                
_sk = os.environ.get("SECRET_KEY", "")
_ak = os.environ.get("API_KEY", "")

_APP_ENV = (os.environ.get("APP_ENV") or os.environ.get("FLASK_ENV") or "").strip().lower()
_IS_PROD = _APP_ENV in {"prod", "production"}
_IS_TEST = _APP_ENV in {"test", "testing"}
_runtime_security_warnings: list[str] = []

if not _sk:
    msg = "SECRET_KEY no definida — usando clave temporal."
    _runtime_security_warnings.append(msg)
    log.warning("%s Define una en producción.", msg)
    if _IS_PROD:
        raise RuntimeError("Configuración insegura en producción: SECRET_KEY ausente")

if not _ak:
    msg = "API_KEY no definida — endpoints API no están protegidos correctamente."
    _runtime_security_warnings.append(msg)
    log.warning(msg)
    if _IS_PROD:
        raise RuntimeError("Configuración insegura en producción: API_KEY ausente")

if _sk and len(_sk) < 32:
    msg = "SECRET_KEY débil: usa al menos 32 caracteres."
    _runtime_security_warnings.append(msg)
    log.warning(msg)
    if _IS_PROD:
        raise RuntimeError("Configuración insegura en producción: SECRET_KEY débil")

if _ak and len(_ak) < 24:
    msg = "API_KEY débil: usa al menos 24 caracteres."
    _runtime_security_warnings.append(msg)
    log.warning(msg)
    if _IS_PROD:
        raise RuntimeError("Configuración insegura en producción: API_KEY débil")

if _sk and _ak and _sk == _ak:
    msg = "SECRET_KEY y API_KEY son iguales — riesgo de seguridad."
    _runtime_security_warnings.append(msg)
    log.warning("⚠️ %s", msg)
    if _IS_PROD:
        raise RuntimeError("Configuración insegura en producción: claves idénticas")

if not state.VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    if not _IS_TEST:
        _runtime_security_warnings.append("VERIFY_SSL=false — solo permitido en laboratorio.")
        log.warning("VERIFY_SSL=false — verificación desactivada (solo lab)")
    if _IS_PROD:
        raise RuntimeError("Configuración insegura en producción: VERIFY_SSL=false")


def _template_ctx() -> dict:
    return {
        "api_key": state.API_KEY,
        "security_warnings": _runtime_security_warnings,
    }


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

# Iniciar limpieza en dev/producción (no en tests)
if not _IS_TEST:
    try:
        from db import _start_cleanup_timer

        _start_cleanup_timer()
    except Exception as _e:
        log.warning("No se pudo iniciar cleanup timer: %s", _e)


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
    return render_template("index.html", **_template_ctx()), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Método no permitido"}), 405

@app.errorhandler(500)
def internal_error(e):
    log.error("Error interno: %s", e, exc_info=True)
    if _req.path.startswith("/api/") or _req.path.startswith("/scan"):
        return jsonify({"error": "Error interno del servidor"}), 500
    return render_template("index.html", **_template_ctx()), 500


                                                                                 
@app.route("/")
def index():
    return render_template("index.html", **_template_ctx())


                                                                                 
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
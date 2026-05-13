"""
state.py — Estado compartido, configuración y helpers de WP VulnScanner
===========================================================================
Contiene:
  - Constantes de configuración (leídas de .env)
  - Estado en memoria (_jobs, semáforo, contadores)
  - Helpers reutilizables (normalize_url, is_safe_url, rate_limit, ...)
  - Decoradores Flask (require_api_key, rate_limit)

Todos los blueprints importan desde aquí para evitar importaciones circulares.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import os
import re as _re_mod
import socket
import sqlite3
import threading
import time
import warnings
from contextlib import contextmanager
from functools import wraps
from urllib.parse import urlparse, urlunparse

log = logging.getLogger("wpvulnscan.state")

                                                                                
APP_VERSION = "6.1"
APP_START   = time.time()

                                                                                
_BASE_DIR = os.path.dirname(__file__)
_DEFAULT_DB_PATH = os.path.join(_BASE_DIR, "scans.db")
_DB_PATH_ENV = os.environ.get("DB_PATH", "").strip()


def _sqlite_conn(path: str | None = None) -> sqlite3.Connection:
    """Abre SQLite con WAL + check_same_thread=False para uso multi-hilo seguro."""
    conn = sqlite3.connect(path or DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


@contextmanager
def _state_db(path: str | None = None):
    """Context manager para conexiones SQLite en state.py.
    Equivalente al _db() de db.py — garantiza commit/rollback y cierre."""
    conn = _sqlite_conn(path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _db_scan_rows(path: str) -> int:
    """Devuelve el número de filas en scans; 0 si no existe tabla/archivo o hay error."""
    try:
        if not path or not os.path.exists(path):
            return 0
        with _state_db(path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM scans").fetchone()
            return int(row[0] or 0) if row else 0
    except Exception:
        return 0


if _DB_PATH_ENV:
    _db_candidate = _DB_PATH_ENV if os.path.isabs(_DB_PATH_ENV) else os.path.join(_BASE_DIR, _DB_PATH_ENV)
    DB_PATH = os.path.abspath(_db_candidate)
else:
    DB_PATH = os.path.abspath(_DEFAULT_DB_PATH)

                                                    
                                                                          
                                                            
_legacy_scans_path = os.path.abspath(_DEFAULT_DB_PATH)
if DB_PATH != _legacy_scans_path:
    _current_rows = _db_scan_rows(DB_PATH)
    _legacy_rows = _db_scan_rows(_legacy_scans_path)
    if _current_rows == 0 and _legacy_rows > 0:
        log.warning(
            "DB_PATH=%s no contiene historial y scans.db sí (%d filas). "
            "Se usará %s para mantener continuidad.",
            DB_PATH,
            _legacy_rows,
            _legacy_scans_path,
        )
        DB_PATH = _legacy_scans_path

_db_dir = os.path.dirname(DB_PATH)
if _db_dir:
    os.makedirs(_db_dir, exist_ok=True)


                                                                                

def _env_int(name: str, default: int, min_val: int = 0, max_val: int = 10_000) -> int:
    """Lee variable de entorno como int con fallback y rango seguro."""
    raw = os.environ.get(name, "")
    try:
        v = int(raw)
        return max(min_val, min(max_val, v))
    except (ValueError, TypeError):
        if raw:
            warnings.warn(
                f"Variable de entorno {name}={raw!r} no es un entero válido — usando {default}"
            )
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    """Lee variable de entorno como bool con fallback seguro."""
    raw = os.environ.get(name, "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return default


def _int(val, default: int = 0, lo: int = 0, hi: int = 10_000) -> int:
    """Convierte un query param a int de forma segura."""
    try:
        return max(lo, min(hi, int(val)))
    except (TypeError, ValueError):
        return default


                                                                                
VERIFY_SSL      = os.environ.get("VERIFY_SSL", "true").lower() != "false"
if not VERIFY_SSL:
    log.warning(
        "⚠ VERIFY_SSL=false — la verificación de certificados SSL está DESACTIVADA. "
        "Usar solo en entornos de prueba o con objetivos en redes internas de confianza."
    )
ALLOW_PRIVATE_IPS = _env_bool("ALLOW_PRIVATE_IPS", False)
SCAN_SCOPE = os.environ.get("SCAN_SCOPE", "").strip().lower()
if SCAN_SCOPE and SCAN_SCOPE not in ("public", "all"):
    log.warning("SCAN_SCOPE=%r no válido — usa public o all. Se ignorará.", SCAN_SCOPE)
    SCAN_SCOPE = ""
API_KEY         = os.environ.get("API_KEY", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
GEMINI_API_KEY    = os.environ.get("GEMINI_API_KEY", "")

RATE_LIMIT_ENABLED = _env_bool("RATE_LIMIT_ENABLED", False)
SCAN_RATE_LIMIT = _env_int("SCAN_RATE_LIMIT", 0, min_val=0)
API_RATE_LIMIT  = _env_int("API_RATE_LIMIT",  0, min_val=0)
MAX_CONCURRENT  = _env_int("MAX_CONCURRENT_SCANS", 5, min_val=1, max_val=50)
SCAN_TIMEOUT_S  = _env_int("SCAN_TIMEOUT_SECONDS", 300, min_val=30, max_val=3600)

                                                                                
_scan_semaphore      = threading.Semaphore(MAX_CONCURRENT)
_active_scans_count  = 0
_active_scans_lock   = threading.Lock()

                                                                                
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()
JOB_TTL    = 3600          

                                                                                
_rate_store: dict[str, list[float]] = {}
_rate_lock  = threading.Lock()

                                                                               
_db_write_lock = threading.Lock()

                                                                                
                                                                                  
                                                                              
_tl = threading.local()


def _get_thread_conn() -> sqlite3.Connection:
    """Devuelve la conexión SQLite del hilo actual, creándola si no existe."""
    conn = getattr(_tl, "conn", None)
    if conn is None:
        conn = _sqlite_conn()
        conn.row_factory = sqlite3.Row
        _tl.conn = conn
    return conn


def _close_thread_conn() -> None:
    """Cierra y descarta la conexión del hilo actual (útil en teardown)."""
    conn = getattr(_tl, "conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            try:
                log.debug("_close_thread_conn: close suppressed")
            except Exception:
                pass
        _tl.conn = None

                                                                                
_JOB_ID_RE = _re_mod.compile(r'^[a-f0-9\-]{8,36}$')


def _validate_job_id(job_id: str) -> bool:
    """job_id debe ser hex (8-36 chars). Evita path traversal / inyección."""
    return bool(_JOB_ID_RE.match(str(job_id)))


def _allow_private_targets() -> bool:
    """Decide si se permiten destinos privados/locales para un escaneo."""
    if SCAN_SCOPE == "all":
        return True
    if SCAN_SCOPE == "public":
        return False
    return ALLOW_PRIVATE_IPS


                                                                                
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),                  
    ipaddress.ip_network("fe80::/10"),                         
    ipaddress.ip_network("100.64.0.0/10"),                   
]


def is_safe_url(url: str) -> tuple[bool, str]:
    """Valida URL con resolución DNS anti-SSRF real."""
    allow_private = _allow_private_targets()
    try:
        url_stripped = url.strip()

                                                                       
                                                                
        if "://" in url_stripped:
            raw_scheme = url_stripped.split("://")[0].lower()
        else:
                                                         
            colon_pos = url_stripped.find(":")
            raw_scheme = url_stripped[:colon_pos].lower() if colon_pos > 0 else ""

        if raw_scheme and raw_scheme not in ("http", "https"):
            return False, "Solo se permiten URLs http/https"

        parsed = urlparse(url_stripped if url_stripped.startswith(("http://", "https://")) else "https://" + url_stripped)
        if parsed.scheme not in ("http", "https"):
            return False, "Solo se permiten URLs http/https"
        if not parsed.hostname:
            return False, "Hostname inválido"
        if not allow_private:
            try:
                infos = socket.getaddrinfo(parsed.hostname, None)
                for info in infos:
                    ip = ipaddress.ip_address(info[4][0])
                    if any(ip in net for net in PRIVATE_NETS):
                        log.warning("Anti-SSRF DNS: %s → %s bloqueado", parsed.hostname, info[4][0])
                        return False, f"IP privada bloqueada tras resolución DNS: {info[4][0]}"
            except socket.gaierror:
                return False, f"No se puede resolver el hostname: {parsed.hostname}"
        return True, ""
    except Exception as e:
        return False, str(e)


def normalize_url(url: str) -> str:
    """Normaliza la URL: añade esquema, lowercase, elimina trailing slash y fragmentos."""
    url = url.strip()
    url_lower = url.lower()
    if url_lower.startswith("http://") or url_lower.startswith("https://"):
        scheme_end = url.index("://") + 3
        url = url[:scheme_end].lower() + url[scheme_end:]
    else:
        url = "https://" + url
    try:
        p = urlparse(url)
        host   = p.hostname or ""
        port   = f":{p.port}" if p.port else ""
        netloc = f"{host}{port}".lower()
        path   = p.path
        if path and path != "/":
            path = path.rstrip("/")
        elif path == "/":
            path = ""
        return urlunparse((p.scheme.lower(), netloc, path, p.params, p.query, ""))
    except Exception:
        return url


                                                                               
def _get_client_ip() -> str:
    """IP real del cliente considerando proxies de confianza.

    Estrategia anti-spoofing:
    1. Si remote_addr es loopback/privado (proxy confiable detrás de Docker/nginx),
       usar X-Real-IP que nginx fija directamente a $remote_addr (no manipulable).
    2. Fallback a X-Forwarded-For usando el ÚLTIMO IP (añadido por nginx/proxy
       confiable), no el primero (que puede ser inyectado por el cliente).
    3. Si no hay proxy, usar remote_addr directamente.
    """
    from flask import request
    import ipaddress as _ip

    remote = request.remote_addr or "unknown"
    try:
        remote_obj = _ip.ip_address(remote)
        is_trusted_proxy = remote_obj.is_loopback or remote_obj.is_private
    except ValueError:
        is_trusted_proxy = False

    if is_trusted_proxy:
                                                                                      
        real_ip = request.headers.get("X-Real-IP", "").strip()
        if real_ip:
            try:
                _ip.ip_address(real_ip)
                return real_ip
            except ValueError:
                pass
                                                                      
                                                                            
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts:
                                                                      
                candidate = parts[-1]
                try:
                    _ip.ip_address(candidate)
                    return candidate
                except ValueError:
                    pass
    return remote


def _sanitize_ip(ip_str: str) -> str:
    """Oculta último octeto de IPv4 para privacidad en logs."""
    try:
        parts = ip_str.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.*"
    except Exception:
        pass
    return "***"


def _sanitize_url(url_str: str, max_len: int = 50) -> str:
    """Oculta parámetros sensibles en URLs antes de loguear."""
    if not url_str:
        return "***"
    try:
        from urllib.parse import urlparse, parse_qs, urlencode
        parsed = urlparse(url_str)
        # Ocultar query params con valores sensibles
        sensitive_keys = {"password", "token", "key", "secret", "api", "auth", "credentials"}
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            cleaned = {}
            for k, v in params.items():
                if any(s in k.lower() for s in sensitive_keys):
                    cleaned[k] = ["***"]
                else:
                    cleaned[k] = v
            parsed = parsed._replace(query=urlencode(cleaned, doseq=True))
        
        result = parsed.geturl()
        return (result[:max_len] + "...") if len(result) > max_len else result
    except Exception:
        return url_str[:max_len] if len(url_str) > max_len else url_str


def _check_rate_limit(ip: str, limit: int, window: int = 60,
                      endpoint: str = "scan") -> bool:
    """Rate limiting persistente en SQLite con fallback en memoria."""
    import sqlite3
    now    = time.time()
    cutoff = now - window
    try:
        with _state_db() as conn:
            conn.execute(
                "DELETE FROM rate_limit WHERE ip=? AND endpoint=? AND ts < ?",
                (ip, endpoint, cutoff)
            )
            count = conn.execute(
                "SELECT COUNT(*) FROM rate_limit WHERE ip=? AND endpoint=? AND ts >= ?",
                (ip, endpoint, cutoff)
            ).fetchone()[0]
            if count >= limit:
                return True
            conn.execute(
                "INSERT INTO rate_limit(ip, endpoint, ts) VALUES(?,?,?)",
                (ip, endpoint, now)
            )
            return False
    except Exception as e:
        log.warning("Rate limit DB error: %s — usando fallback en memoria", e)
        with _rate_lock:
            timestamps = [t for t in _rate_store.get(ip, []) if now - t < window]
            if len(timestamps) >= limit:
                return True
            timestamps.append(now)
            _rate_store[ip] = timestamps
        return False


                                                                                

def rate_limit(limit: int):
    """Decorador de rate limiting persistente."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            from flask import request, jsonify
            if not RATE_LIMIT_ENABLED or limit <= 0:
                return f(*args, **kwargs)
            ip       = _get_client_ip()
            endpoint = request.endpoint or "unknown"
            if _check_rate_limit(ip, limit, endpoint=endpoint):
                log.warning("Rate limit alcanzado: %s en %s", ip, request.path)
                return jsonify({
                    "error": "Demasiadas peticiones. Espera un minuto.",
                    "retry_after": 60
                }), 429, {
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + 60),
                }
            return f(*args, **kwargs)
        return wrapper
    return decorator


def require_api_key(f):
    """Decorador: requiere X-API-Key si API_KEY está configurada.
    Lee API_KEY dinámicamente del módulo en cada petición para que
    los tests puedan parchear state.API_KEY sin recargar el módulo.
    """
    import sys as _sys
    @wraps(f)
    def wrapper(*args, **kwargs):
        from flask import request, jsonify
                                                                            
        _mod = _sys.modules[__name__]
        current_key = getattr(_mod, "API_KEY", "")
        if not current_key:
            return f(*args, **kwargs)
        key = (
            request.headers.get("X-API-Key")
            or request.args.get("api_key")
            or request.args.get("key")
        )
        if not hmac.compare_digest(key or "", current_key):
            return jsonify({"error": "API key inválida"}), 401
        return f(*args, **kwargs)
    return wrapper


                                                                                
import time as _time
import hashlib as _hashlib

_scan_cache: dict[str, dict] = {}
_scan_cache_lock = threading.Lock()
SCAN_CACHE_TTL = _env_int("SCAN_CACHE_TTL", 0, min_val=0, max_val=2_592_000)
_scan_cache_table_checked = False


def _ensure_scan_cache_table() -> None:
    global _scan_cache_table_checked
    if _scan_cache_table_checked:
        return
    with _db_write_lock:
        if _scan_cache_table_checked:
            return
        with _state_db() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_cache (
                    url_key      TEXT PRIMARY KEY,
                    url          TEXT NOT NULL,
                    cached_ts    REAL NOT NULL,
                    result_json  TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_cache_cached_ts ON scan_cache(cached_ts DESC)")
            _scan_cache_table_checked = True


def cache_get(url: str) -> dict | None:
    """Devuelve resultado cacheado si existe y no ha expirado."""
    if SCAN_CACHE_TTL <= 0:
        return None
    key = _hashlib.md5(url.lower().encode()).hexdigest()

                                                            
    try:
        _ensure_scan_cache_table()
        now = _time.time()
        cutoff = now - SCAN_CACHE_TTL
        with _state_db() as conn:
            row = conn.execute(
                "SELECT result_json, cached_ts FROM scan_cache WHERE url_key=?",
                (key,),
            ).fetchone()
            if row:
                raw_json, cached_ts = row
                if float(cached_ts or 0) >= cutoff:
                    return json.loads(raw_json)
                conn.execute("DELETE FROM scan_cache WHERE url_key=?", (key,))
    except Exception as e:
        log.warning("cache_get SQLite error: %s — usando fallback en memoria", e)

                            
    with _scan_cache_lock:
        entry = _scan_cache.get(key)
        if entry and (_time.time() - entry["ts"]) < SCAN_CACHE_TTL:
            return entry["data"]
        if entry:
            del _scan_cache[key]
    return None


def cache_set(url: str, result: dict) -> None:
    """Guarda resultado en cache con timestamp."""
    if SCAN_CACHE_TTL <= 0:
        return
    key = _hashlib.md5(url.lower().encode()).hexdigest()

                                 
    try:
        _ensure_scan_cache_table()
        now = _time.time()
        with _db_write_lock:
            with _state_db() as conn:
                conn.execute(
                    """
                    INSERT INTO scan_cache (url_key, url, cached_ts, result_json)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(url_key) DO UPDATE SET
                        url=excluded.url,
                        cached_ts=excluded.cached_ts,
                        result_json=excluded.result_json
                    """,
                    (key, url, now, json.dumps(result, ensure_ascii=False)),
                )
                conn.execute("DELETE FROM scan_cache WHERE cached_ts < ?", (now - SCAN_CACHE_TTL,))
    except Exception as e:
        log.warning("cache_set SQLite error: %s — manteniendo fallback en memoria", e)

                            
    with _scan_cache_lock:
        _scan_cache[key] = {"ts": _time.time(), "data": result}
                                                  
        if len(_scan_cache) > 500:
            now = _time.time()
            expired = [k for k, v in _scan_cache.items() if now - v["ts"] >= SCAN_CACHE_TTL]
            for k in expired:
                del _scan_cache[k]


def cache_invalidate(url: str) -> None:
    """Elimina una URL del cache (ej: al pedir re-scan)."""
    key = _hashlib.md5(url.lower().encode()).hexdigest()

                         
    try:
        _ensure_scan_cache_table()
        with _db_write_lock:
            with _state_db() as conn:
                conn.execute("DELETE FROM scan_cache WHERE url_key=?", (key,))
    except Exception as e:
        log.warning("cache_invalidate SQLite error: %s", e)

                                      
    with _scan_cache_lock:
        _scan_cache.pop(key, None)


                                                                                
                                                                                
                                                    

_TOP_PLUGINS_TTL = 120            
_TOP_PLUGINS_KEY = "__top_plugins__"
_top_plugins_table_checked = False


def _ensure_top_plugins_table() -> None:
    global _top_plugins_table_checked
    if _top_plugins_table_checked:
        return
    with _db_write_lock:
        if _top_plugins_table_checked:
            return
        with _state_db() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS kv_cache (
                    key       TEXT PRIMARY KEY,
                    value     TEXT NOT NULL,
                    cached_ts REAL NOT NULL
                )
            """)
            _top_plugins_table_checked = True


def top_plugins_cache_get() -> list | None:
    """Devuelve la lista de top plugins cacheada, o None si expiró o no existe."""
    try:
        _ensure_top_plugins_table()
        now = _time.time()
        with _state_db() as conn:
            row = conn.execute(
                "SELECT value, cached_ts FROM kv_cache WHERE key=?",
                (_TOP_PLUGINS_KEY,),
            ).fetchone()
        if row:
            value_json, cached_ts = row
            if (now - float(cached_ts)) < _TOP_PLUGINS_TTL:
                return json.loads(value_json)
    except Exception as e:
        log.warning("top_plugins_cache_get error: %s", e)
    return None


def top_plugins_cache_set(data: list) -> None:
    """Guarda la lista de top plugins en kv_cache (compartida entre workers)."""
    try:
        _ensure_top_plugins_table()
        now = _time.time()
        with _db_write_lock:
            with _state_db() as conn:
                conn.execute(
                    """
                    INSERT INTO kv_cache (key, value, cached_ts)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value=excluded.value,
                        cached_ts=excluded.cached_ts
                    """,
                    (_TOP_PLUGINS_KEY, json.dumps(data, ensure_ascii=False), now),
                )
    except Exception as e:
        log.warning("top_plugins_cache_set error: %s", e)

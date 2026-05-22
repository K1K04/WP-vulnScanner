"""
db.py — Capa de acceso a datos SQLite para WP VulnScanner
=============================================================
Contiene:
  - Context manager _db()
  - init_db() — creación de tablas e índices
    - save_scan(), get_history(), get_scan_from_db()
    - upsert_job_state(), get_job_state()
  - _cleanup_jobs(), _start_cleanup_timer()
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from contextlib import contextmanager

from state import DB_PATH, _db_write_lock, _jobs, _jobs_lock, JOB_TTL, SCAN_CACHE_TTL

log = logging.getLogger("wpvulnscan.db")
_scan_jobs_table_checked = False
_ai_chat_table_checked = False


                                                                                

@contextmanager
def _db():
    """Context manager para conexiones SQLite con WAL y row_factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _ensure_scan_jobs_table() -> None:
    global _scan_jobs_table_checked
    if _scan_jobs_table_checked:
        return
    with _db_write_lock:
        if _scan_jobs_table_checked:
            return
        with _db() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    id            TEXT PRIMARY KEY,
                    url           TEXT NOT NULL,
                    status        TEXT NOT NULL,
                    started_ts    REAL NOT NULL,
                    updated_ts    REAL NOT NULL,
                    legal_accepted INTEGER DEFAULT 0,
                    user_ip       TEXT,
                    error         TEXT,
                    result_json   TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_updated_ts ON scan_jobs(updated_ts DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_url ON scan_jobs(url)")
        _scan_jobs_table_checked = True


def _ensure_ai_chat_table() -> None:
    global _ai_chat_table_checked
    if _ai_chat_table_checked:
        return
    with _db_write_lock:
        if _ai_chat_table_checked:
            return
        with _db() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ai_chat_history (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id     TEXT NOT NULL,
                    session_id  TEXT NOT NULL DEFAULT 'default',
                    role        TEXT NOT NULL,
                    content     TEXT NOT NULL,
                    provider    TEXT,
                    model       TEXT,
                    created_ts  REAL NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ai_chat_scan_session_ts "
                "ON ai_chat_history(scan_id, session_id, created_ts DESC)"
            )
        _ai_chat_table_checked = True


                                                                                

def init_db():
    """Crea todas las tablas e índices necesarios."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id             TEXT PRIMARY KEY,
            url            TEXT NOT NULL,
            scanned_at     TEXT NOT NULL,
            duration       REAL,
            risk_score     INTEGER,
            risk_label     TEXT,
            vuln_count     INTEGER,
            critical_count INTEGER,
            high_count     INTEGER,
            plugin_count   INTEGER,
            theme_count    INTEGER,
            exposed_count  INTEGER,
            users_count    INTEGER,
            malware_count  INTEGER,
            wp_version     TEXT,
            wp_outdated    INTEGER DEFAULT 0,
            xmlrpc_enabled INTEGER DEFAULT 0,
            wpscan_api     INTEGER DEFAULT 0,
            legal_accepted INTEGER DEFAULT 0,
            user_ip        TEXT,
            result_json    TEXT,
            job_status     TEXT    DEFAULT 'done'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS active_scans (
            id              TEXT PRIMARY KEY,
            scan_id         TEXT NOT NULL REFERENCES scans(id),
            started_at      TEXT NOT NULL,
            finished_at     TEXT,
            user_ip         TEXT NOT NULL,
            target_url      TEXT NOT NULL,
            modules_run     TEXT,
            bf_attempts     INTEGER DEFAULT 0,
            bf_found        INTEGER DEFAULT 0,
            hidden_plugins  INTEGER DEFAULT 0,
            backup_files    INTEGER DEFAULT 0,
            injection_tests INTEGER DEFAULT 0,
            result_summary  TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id           TEXT PRIMARY KEY,
            url          TEXT NOT NULL,
            cron_expr    TEXT NOT NULL DEFAULT 'weekly',
            active       INTEGER DEFAULT 1,
            created_at   TEXT NOT NULL,
            last_run     TEXT,
            last_scan_id TEXT,
            notify_email TEXT,
            callback_url TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rate_limit (
            ip         TEXT NOT NULL,
            endpoint   TEXT NOT NULL DEFAULT 'scan',
            ts         REAL NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rl_ip_endpoint_ts ON rate_limit(ip, endpoint, ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_url        ON scans(url)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_url_scanned ON scans(url, scanned_at DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_risk_label ON scans(risk_label)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_risk_score ON scans(risk_score DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_status     ON scans(job_status)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS push_subscriptions (
            id           TEXT PRIMARY KEY,
            endpoint     TEXT NOT NULL UNIQUE,
            p256dh       TEXT NOT NULL,
            auth         TEXT NOT NULL,
            created_at   TEXT NOT NULL,
            active       INTEGER DEFAULT 1,
            user_agent   TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_push_ep ON push_subscriptions(endpoint)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pwa_cache (
            url          TEXT PRIMARY KEY,
            scan_id      TEXT NOT NULL,
            cached_at    TEXT NOT NULL,
            result_json  TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id            TEXT PRIMARY KEY,
            url           TEXT NOT NULL,
            status        TEXT NOT NULL,
            started_ts    REAL NOT NULL,
            updated_ts    REAL NOT NULL,
            legal_accepted INTEGER DEFAULT 0,
            user_ip       TEXT,
            error         TEXT,
            result_json   TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_updated_ts ON scan_jobs(updated_ts DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_url ON scan_jobs(url)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_cache (
            url_key      TEXT PRIMARY KEY,
            url          TEXT NOT NULL,
            cached_ts    REAL NOT NULL,
            result_json  TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_cache_cached_ts ON scan_cache(cached_ts DESC)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_chat_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     TEXT NOT NULL,
            session_id  TEXT NOT NULL DEFAULT 'default',
            role        TEXT NOT NULL,
            content     TEXT NOT NULL,
            provider    TEXT,
            model       TEXT,
            created_ts  REAL NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ai_chat_scan_session_ts "
        "ON ai_chat_history(scan_id, session_id, created_ts DESC)"
    )
    try:
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

                                  
    from scanner.api_keys import init_api_keys_table, load_keys_to_env
    conn2 = sqlite3.connect(DB_PATH)
    try:
        init_api_keys_table(conn2)
    finally:
        conn2.close()
    load_keys_to_env(DB_PATH)

                       
    from blueprints.webhooks import init_webhooks_table
    conn3 = sqlite3.connect(DB_PATH)
    try:
        init_webhooks_table(conn3)
        conn3.commit()
    finally:
        conn3.close()

    log.info("Base de datos inicializada: %s", DB_PATH)


                                                                                

def save_scan(scan_id: str, result: dict, legal: bool, user_ip: str,
              job_status: str = "done"):
    """Guarda escaneo con lock para evitar contención en SQLite."""
    s = result.get("summary", {})
    log.info("[save_scan] guardando %s → %s (status=%s)", scan_id,
             result.get("target_url", ""), job_status)
    try:
        with _db_write_lock:
            with _db() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO scans VALUES
                    (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    scan_id,
                    result.get("target_url", ""),
                    result.get("scanned_at", ""),
                    result.get("duration", 0),
                    result.get("risk_score", 0),
                    result.get("risk_label", ""),
                    s.get("vulns_found", 0),
                    s.get("critical_vulns", 0),
                    s.get("high_vulns", 0),
                    s.get("plugins_found", 0),
                    s.get("themes_found", 0),
                    s.get("exposed_files", 0),
                    s.get("users_found", 0),
                    s.get("malware_found", 0),
                    result.get("wp_version", ""),
                    1 if result.get("wp_outdated") else 0,
                    1 if result.get("xmlrpc_enabled") else 0,
                    1 if result.get("wpscan_api_used") else 0,
                    1 if legal else 0,
                    user_ip,
                    json.dumps(result, ensure_ascii=False),
                    job_status,
                ))
                log.info("[save_scan] OK: %s guardado en BD", scan_id)
    except Exception as _db_err:
        log.error("[save_scan] ERROR guardando %s: %s", scan_id, _db_err, exc_info=True)
        raise


def upsert_job_state(
    job_id: str,
    url: str,
    status: str,
    *,
    legal: bool = False,
    user_ip: str = "",
    error: str = "",
    result: dict | None = None,
    started_ts: float | None = None,
):
    """Persiste estado de job para recuperación tras reinicios."""
    _ensure_scan_jobs_table()
    now_ts = time.time()
    start_ts = float(started_ts if started_ts is not None else now_ts)
    result_json = json.dumps(result, ensure_ascii=False) if result is not None else None
    with _db_write_lock:
        with _db() as conn:
            conn.execute(
                """
                INSERT INTO scan_jobs
                    (id, url, status, started_ts, updated_ts, legal_accepted, user_ip, error, result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    url=excluded.url,
                    status=excluded.status,
                    updated_ts=excluded.updated_ts,
                    legal_accepted=excluded.legal_accepted,
                    user_ip=excluded.user_ip,
                    error=excluded.error,
                    result_json=COALESCE(excluded.result_json, scan_jobs.result_json)
                """,
                (
                    job_id,
                    url,
                    status,
                    start_ts,
                    now_ts,
                    1 if legal else 0,
                    user_ip,
                    error,
                    result_json,
                ),
            )


def get_job_state(job_id: str) -> dict | None:
    """Recupera estado persistido de un job."""
    _ensure_scan_jobs_table()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT id, url, status, started_ts, updated_ts, legal_accepted, user_ip, error, result_json
            FROM scan_jobs
            WHERE id=?
            """,
            (job_id,),
        ).fetchone()
        if not row:
            return None

        out = {
            "id": row["id"],
            "url": row["url"],
            "status": row["status"],
            "started": float(row["started_ts"] or 0.0),
            "updated": float(row["updated_ts"] or 0.0),
            "legal_accepted": bool(row["legal_accepted"]),
            "user_ip": row["user_ip"] or "",
            "error": row["error"] or "",
            "result": None,
        }
        raw = row["result_json"]
        if raw:
            try:
                out["result"] = json.loads(raw)
            except Exception as _e:
                try:
                    log = globals().get("log")
                    if log:
                        log.debug("db.get_scan_row json parse suppressed: %s", _e)
                except Exception:
                    pass
                out["result"] = None
        return out
    finally:
        conn.close()


def get_history(limit: int = 50, offset: int = 0,
                risk_label: str = "", url_filter: str = "") -> dict:
    """Devuelve historial paginado con soporte de filtros."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    where_clauses = []
    params: list = []
    if risk_label:
        where_clauses.append("risk_label = ?")
        params.append(risk_label)
    if url_filter:
        where_clauses.append("url LIKE ?")
        params.append(f"%{url_filter}%")

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    try:
        total = conn.execute(
            f"SELECT COUNT(*) FROM scans {where_sql}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"""SELECT id, url, scanned_at, duration, risk_score, risk_label,
                   vuln_count, critical_count, high_count, plugin_count,
                   theme_count, exposed_count, users_count, malware_count,
                   wp_version, wp_outdated, xmlrpc_enabled, wpscan_api,
                   legal_accepted, user_ip
            FROM scans {where_sql} ORDER BY scanned_at DESC LIMIT ? OFFSET ?""",
            params + [limit, offset]
        ).fetchall()
        return {
            "data":     [dict(r) for r in rows],
            "total":    total,
            "limit":    limit,
            "offset":   offset,
            "has_next": (offset + limit) < total,
            "has_prev": offset > 0,
        }
    finally:
        conn.close()


def get_scan_from_db(scan_id: str) -> dict | None:
    """Recupera un resultado de escaneo desde SQLite por su ID."""
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            "SELECT result_json FROM scans WHERE id=?", (scan_id,)
        ).fetchone()
        if not row:
            return None
        try:
            return normalize_scan_result(json.loads(row[0]), scan_id=scan_id)
        except (json.JSONDecodeError, TypeError) as e:
            log.error("result_json corrupto para scan_id=%s: %s", scan_id, e)
            return None
    finally:
        conn.close()


def normalize_scan_result(result: dict | None, *, scan_id: str = "", scanned_at: str = "", target_url: str = "") -> dict:
    """Normaliza la forma del resultado para consumidores legacy y UI."""
    data = dict(result or {})

    def _as_int(value, default=0):
        try:
            if value is None or value == "":
                return default
            number = int(float(value))
            return number if number == number else default
        except Exception:
            return default

    def _count(value):
        if isinstance(value, list):
            return len(value)
        return _as_int(value)

    if scan_id:
        data.setdefault("scan_id", scan_id)
    if scanned_at:
        data.setdefault("scanned_at", scanned_at)
    if not data.get("target_url"):
        data["target_url"] = target_url or data.get("url") or data.get("site_url") or data.get("target") or ""

    summary_raw = data.get("summary")
    summary = summary_raw if isinstance(summary_raw, dict) else {}
    summary_defaults = {
        "plugins_found": data.get("plugins_found", _count(data.get("plugins"))),
        "themes_found": data.get("themes_found", _count(data.get("themes"))),
        "vulns_found": data.get("vulns_found", _count(data.get("vulnerabilities"))),
        "critical_vulns": data.get("critical_vulns", 0),
        "high_vulns": data.get("high_vulns", 0),
        "medium_vulns": data.get("medium_vulns", 0),
        "exposed_files": data.get("exposed_files", _count(data.get("exposed_files"))),
        "header_issues": data.get("header_issues", _count(data.get("headers_issues"))),
        "users_found": data.get("users_found", _count(data.get("users"))),
        "malware_found": data.get("malware_found", _count(data.get("malware_indicators"))),
        "outdated_plugins": data.get("outdated_plugins", 0),
        "outdated_themes": data.get("outdated_themes", 0),
        "wpscan_api_used": data.get("wpscan_api_used", False),
    }
    normalized_summary = {}
    for key, default_value in summary_defaults.items():
        normalized_summary[key] = _as_int(summary.get(key, default_value)) if key != "wpscan_api_used" else bool(summary.get(key, default_value))
    data["summary"] = normalized_summary

    int_fields = (
        "risk_score", "plugins_found", "themes_found", "vulns_found", "critical_vulns",
        "high_vulns", "medium_vulns", "exposed_files", "header_issues", "users_found",
        "malware_found", "outdated_plugins", "outdated_themes",
    )
    for key in int_fields:
        data[key] = _as_int(data.get(key, normalized_summary.get(key, 0)))

    if "duration" in data:
        data["duration"] = _as_int(data.get("duration"), 0)
    elif "duration_s" in data:
        data["duration"] = _as_int(data.get("duration_s"), 0)

    if not isinstance(data.get("vulnerabilities"), list):
        data["vulnerabilities"] = []
    if not isinstance(data.get("plugins"), list):
        data["plugins"] = []
    if not isinstance(data.get("themes"), list):
        data["themes"] = []
    if not isinstance(data.get("exposed_files"), list):
        data["exposed_files_count"] = _as_int(data.get("exposed_files"))
        data["exposed_files"] = []
    if not isinstance(data.get("users"), list):
        data["users_count"] = _as_int(data.get("users"))
        data["users"] = []
    if not isinstance(data.get("headers_issues"), list):
        data["headers_issues_count"] = _as_int(data.get("headers_issues"))
        data["headers_issues"] = []
    if not isinstance(data.get("malware_indicators"), list):
        data["malware_indicators_count"] = _as_int(data.get("malware_indicators"))
        data["malware_indicators"] = []

    return data


def get_previous_scan_same_url(scan_id: str) -> dict | None:
    """Devuelve el escaneo inmediatamente anterior del mismo dominio/URL."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        current = conn.execute(
            "SELECT id, url, scanned_at FROM scans WHERE id=?",
            (scan_id,),
        ).fetchone()
        if not current:
            return None

        current_url = (current["url"] or "").strip()
        current_ts = (current["scanned_at"] or "").strip()
        if not current_url:
            return None

        prev = None
        if current_ts:
            prev = conn.execute(
                """
                SELECT id, scanned_at, result_json
                FROM scans
                WHERE url=? AND id<>? AND scanned_at < ?
                ORDER BY scanned_at DESC
                LIMIT 1
                """,
                (current_url, scan_id, current_ts),
            ).fetchone()

        if not prev:
            prev = conn.execute(
                """
                SELECT id, scanned_at, result_json
                FROM scans
                WHERE url=? AND id<>?
                ORDER BY scanned_at DESC
                LIMIT 1
                """,
                (current_url, scan_id),
            ).fetchone()

        if not prev:
            return None

        try:
            obj = json.loads(prev["result_json"] or "{}")
        except Exception:
            return None

        if not isinstance(obj, dict):
            return None

        return normalize_scan_result(obj, scan_id=prev["id"], scanned_at=prev["scanned_at"] or "")
    finally:
        conn.close()


def get_latest_scan_same_url(url: str, exclude_scan_id: str = "") -> dict | None:
    """Devuelve el escaneo más reciente de una URL, opcionalmente excluyendo uno."""
    url = (url or "").strip()
    if not url:
        return None

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        if exclude_scan_id:
            row = conn.execute(
                """
                SELECT id, scanned_at, result_json
                FROM scans
                WHERE url=? AND id<>?
                ORDER BY scanned_at DESC
                LIMIT 1
                """,
                (url, exclude_scan_id),
            ).fetchone()
        else:
            row = conn.execute(
                """
                SELECT id, scanned_at, result_json
                FROM scans
                WHERE url=?
                ORDER BY scanned_at DESC
                LIMIT 1
                """,
                (url,),
            ).fetchone()
        if not row:
            return None
        try:
            obj = json.loads(row["result_json"] or "{}")
        except Exception:
            return None
        if not isinstance(obj, dict):
            return None
        return normalize_scan_result(
            obj,
            scan_id=row["id"],
            scanned_at=row["scanned_at"] or "",
            target_url=url,
        )
    finally:
        conn.close()


def save_ai_chat_message(
    scan_id: str,
    role: str,
    content: str,
    *,
    session_id: str = "default",
    provider: str = "",
    model: str = "",
) -> None:
    """Guarda un mensaje de chat IA asociado a un scan_id."""
    scan_id = (scan_id or "").strip()
    role = (role or "").strip().lower()
    content = (content or "").strip()
    session_id = (session_id or "default").strip() or "default"
    if not scan_id or role not in ("user", "assistant") or not content:
        return

    _ensure_ai_chat_table()
    with _db_write_lock:
        with _db() as conn:
            conn.execute(
                """
                INSERT INTO ai_chat_history
                    (scan_id, session_id, role, content, provider, model, created_ts)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    session_id,
                    role,
                    content,
                    (provider or "").strip(),
                    (model or "").strip(),
                    time.time(),
                ),
            )


def get_ai_chat_history(scan_id: str, *, session_id: str = "default", limit: int = 80) -> list[dict]:
    """Devuelve el historial de chat IA para un scan_id (orden cronológico)."""
    scan_id = (scan_id or "").strip()
    session_id = (session_id or "default").strip() or "default"
    if not scan_id:
        return []

    try:
        limit_i = int(limit or 80)
    except Exception:
        limit_i = 80
    limit = max(1, min(limit_i, 500))
    _ensure_ai_chat_table()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT role, content, provider, model, created_ts
            FROM ai_chat_history
            WHERE scan_id=? AND session_id=?
            ORDER BY created_ts DESC
            LIMIT ?
            """,
            (scan_id, session_id, limit),
        ).fetchall()
        out = [
            {
                "role": r["role"],
                "content": r["content"],
                "provider": r["provider"] or "",
                "model": r["model"] or "",
                "created_ts": float(r["created_ts"] or 0),
            }
            for r in rows
        ]
        out.reverse()
        return out
    finally:
        conn.close()


def delete_ai_chat_history(scan_id: str, *, session_id: str = "default") -> int:
    """Borra historial de chat IA de un scan_id y devuelve filas eliminadas."""
    scan_id = (scan_id or "").strip()
    session_id = (session_id or "default").strip() or "default"
    if not scan_id:
        return 0

    _ensure_ai_chat_table()
    with _db_write_lock:
        with _db() as conn:
            cur = conn.execute(
                "DELETE FROM ai_chat_history WHERE scan_id=? AND session_id=?",
                (scan_id, session_id),
            )
            return int(cur.rowcount or 0)


                                                                                

def _cleanup_jobs():
    """Elimina jobs expirados de memoria y purga rate_limit antiguo.
    
    TTL Policy:
    - Jobs 'running': nunca se eliminan (evita corruption)
    - Jobs 'done'/'error' > JOB_TTL: se eliminan (previene memory leak)
    - Si job sin status > 2*JOB_TTL: se elimina como dead (edge case)
    """
    now = time.time()
    cutoff = now - JOB_TTL
    dead_cutoff = now - (2 * JOB_TTL)
    
    with _jobs_lock:
        to_del = [
            jid for jid, j in _jobs.items()
            if (
                (j.get("started", 0) < cutoff and j.get("status") in ("done", "error"))
                or (j.get("started", 0) < dead_cutoff and j.get("status") not in ("running",))
            )
        ]
        for jid in to_del:
            del _jobs[jid]
    
    if to_del:
        log.info("💾 Jobs limpiados de memoria: %d (TTL=%dsec)", len(to_del), JOB_TTL)
    try:
        _ensure_scan_jobs_table()
        rl_cutoff = time.time() - 86400
        cache_cutoff = time.time() - max(0, int(SCAN_CACHE_TTL or 0))
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM rate_limit WHERE ts < ?", (rl_cutoff,))
        conn.execute(
            "DELETE FROM scan_jobs WHERE updated_ts < ? AND status != 'running'",
            (cutoff,),
        )
        if SCAN_CACHE_TTL > 0:
            conn.execute("DELETE FROM scan_cache WHERE cached_ts < ?", (cache_cutoff,))
        conn.commit()
        conn.close()
    except Exception as _e:
        log.warning("_cleanup_jobs: error purgando rate_limit: %s", _e)


def _start_cleanup_timer():
    """Inicia el timer de limpieza de jobs (cada 5 minutos) en background."""
    def _run():
        while True:
            time.sleep(300)
            try:
                _cleanup_jobs()
            except Exception as _e:
                log.warning("cleanup timer error: %s", _e)
    t = threading.Thread(target=_run, daemon=True, name="job-cleanup-timer")
    t.start()
    log.info("Job cleanup timer iniciado (intervalo: 5 min)")

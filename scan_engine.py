"""
scan_engine.py — Motor de escaneo asíncrono para WP VulnScanner
====================================================================
Contiene:
  - _run_scan()  — ejecuta un escaneo dentro del semáforo de concurrencia
  - _fire_webhook() — dispara webhook POST con el resultado
  - _pwa_cache_result() — guarda el último resultado en pwa_cache
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
from datetime import datetime

import requests as _req

import state
from state import (
    VERIFY_SSL, SCAN_TIMEOUT_S,
    _scan_semaphore, _active_scans_count, _active_scans_lock,
    _jobs, _jobs_lock, _db_write_lock, _env_int, _env_bool,
)
from error_codes import ErrorCode, ScanError, format_error
from db import _db, get_latest_scan_same_url, save_scan, upsert_job_state

log = logging.getLogger("wpvulnscan.engine")
_RECOVERY_LOCK = threading.Lock()
_RECOVERY_DONE = False


def _fire_webhook(callback_url: str, result: dict):
    """Dispara webhook POST con el resultado del escaneo."""
    try:
        _req.post(
            callback_url,
            json={"status": "done", "result": result},
            timeout=10,
            headers={"Content-Type": "application/json"},
        )
        log.info("Webhook disparado: %s", callback_url)
    except Exception as e:
        log.warning("Error en webhook %s: %s", callback_url, e)


def _pwa_cache_result(url: str, scan_id: str, result_json: str) -> None:
    """Guarda el último resultado en pwa_cache tras cada escaneo."""
    try:
        with _db_write_lock:
            with _db() as conn:
                conn.execute("""
                    INSERT INTO pwa_cache (url, scan_id, cached_at, result_json)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(url) DO UPDATE SET
                        scan_id=excluded.scan_id,
                        cached_at=excluded.cached_at,
                        result_json=excluded.result_json
                """, (url, scan_id, datetime.now().isoformat(), result_json))
    except Exception as e:
        log.warning("pwa_cache_result error: %s", e)


def recover_interrupted_jobs_on_startup() -> int:
    """Marca jobs 'running' como interrumpidos tras reinicio y los rehidrata en memoria."""
    global _RECOVERY_DONE
    if _RECOVERY_DONE:
        return 0

    with _RECOVERY_LOCK:
        if _RECOVERY_DONE:
            return 0

        recovered = 0
        msg = "Escaneo interrumpido por reinicio del servidor. Ejecuta un re-scan para retomarlo."

        try:
            with _db() as conn:
                rows = conn.execute(
                    """
                    SELECT id, url, started_ts, legal_accepted, user_ip, result_json
                    FROM scan_jobs
                    WHERE status='running'
                    ORDER BY updated_ts DESC
                    LIMIT 500
                    """
                ).fetchall()
        except Exception as exc:
            log.debug("recover_interrupted_jobs_on_startup: sin tabla scan_jobs o DB no lista (%s)", exc)
            _RECOVERY_DONE = True
            return 0

        for row in rows:
            job_id = str(row["id"] or "").strip()
            if not job_id:
                continue

            result_obj = None
            try:
                raw = row["result_json"]
                if raw:
                    result_obj = json.loads(raw)
            except Exception as _e:
                try:
                    log.debug("recover_interrupted_jobs: json parse suppressed: %s", _e)
                except Exception:
                    pass
                result_obj = None

            q = queue.Queue()
            q.put({"type": "error", "message": msg, "recovered": True})

            with _jobs_lock:
                _jobs[job_id] = {
                    "status": "error",
                    "url": row["url"] or "",
                    "started": float(row["started_ts"] or time.time()),
                    "result": result_obj,
                    "error": msg,
                    "queue": q,
                }

            try:
                upsert_job_state(
                    job_id,
                    row["url"] or "",
                    "error",
                    legal=bool(row["legal_accepted"]),
                    user_ip=row["user_ip"] or "",
                    error=msg,
                    result=result_obj,
                    started_ts=float(row["started_ts"] or time.time()),
                )
            except Exception as exc:
                log.warning("No se pudo marcar job recuperado %s: %s", job_id, exc)

            recovered += 1

        if recovered:
            log.warning("Recuperación post-reinicio: %d job(s) running marcados como interrumpidos", recovered)

        _RECOVERY_DONE = True
        return recovered


def _run_scan(job_id: str, url: str, legal: bool, user_ip: str,
              callback_url: str = ""):
    """
    Ejecuta el escaneo dentro del semáforo de concurrencia con timeout global.
    Actualiza _jobs[job_id] con el estado y resultado.
    """
    global _active_scans_count

    from scanner.core import WPScanner, ScannerConfig
    from scanner.reputation import check_reputation
    from scanner.subdomain import enumerate_subdomains
    import concurrent.futures as _cf

    acquired = False
    with _active_scans_lock:
        acquired = _scan_semaphore.acquire(timeout=10)
        if acquired:
            _active_scans_count += 1

    if not acquired:
        debug_mode = state.DEBUG_MODE
        error_obj = ScanError(
            ErrorCode.SCAN_BUSY,
            job_id=job_id,
            url=url,
            active_scans=_active_scans_count,
            max_concurrent=_env_int("MAX_CONCURRENT_SCANS", 5, min_val=1, max_val=50),
        )
        with _jobs_lock:
            _jobs[job_id]["status"] = "error"
            _jobs[job_id]["error"] = error_obj.message
            _jobs[job_id]["error_code"] = error_obj.code.code_str
            _jobs[job_id]["queue"].put({
                "type": "error",
                "message": error_obj.message,
                "error_code": error_obj.code.code_str,
                **(error_obj.to_dict(debug_mode=debug_mode).get("debug", {})),
            })
        try:
            upsert_job_state(
                job_id,
                url,
                "error",
                legal=legal,
                user_ip=user_ip,
                error=error_obj.message,
            )
        except Exception as e:
            log.warning("No se pudo persistir estado de job ocupado %s: %s", job_id, e)
        return

    try:
        eq: queue.Queue = _jobs[job_id]["queue"]
        _scan_start = time.time()
        try:
            upsert_job_state(
                job_id,
                url,
                "running",
                legal=legal,
                user_ip=user_ip,
                started_ts=_scan_start,
            )
        except Exception as e:
            log.warning("No se pudo persistir estado running %s: %s", job_id, e)

        def cb(msg: str, pct: int):
            if time.time() - _scan_start > SCAN_TIMEOUT_S:
                raise TimeoutError(f"Escaneo superó el límite de {SCAN_TIMEOUT_S}s")
            eq.put({"type": "progress", "message": msg, "percent": pct})

        def finding_cb(finding: dict):
            try:
                eq.put({"type": "finding", **finding})
            except Exception:
                pass

        config  = ScannerConfig(
            timeout=_env_int("SCANNER_TIMEOUT", 12, min_val=3, max_val=120),
            verify_ssl=VERIFY_SSL,
            wpscan_api_token=os.environ.get("WPSCAN_API_TOKEN", ""),
            max_workers=_env_int("SCANNER_MAX_WORKERS", 3, min_val=1, max_val=32),
            request_delay=float(os.environ.get("SCANNER_REQUEST_DELAY", "0.5")),
            run_nmap=_env_bool("SCANNER_RUN_NMAP", True),
            run_nikto=_env_bool("SCANNER_RUN_NIKTO", False),
            force_generic_passive=_env_bool("SCANNER_FORCE_GENERIC_PASSIVE", True),
        )
        scanner = WPScanner(config)

        try:
            hard_timeout_s = _env_int(
                "SCAN_HARD_TIMEOUT_SECONDS",
                SCAN_TIMEOUT_S,
                min_val=30,
                max_val=7200,
            )
            _scan_ex = _cf.ThreadPoolExecutor(max_workers=1, thread_name_prefix="scan-core")
            try:
                _scan_future = _scan_ex.submit(
                    scanner.scan,
                    url,
                    progress_callback=cb,
                    finding_callback=finding_cb,
                )
                try:
                    result = _scan_future.result(timeout=hard_timeout_s)
                except _cf.TimeoutError:
                    _scan_future.cancel()
                    raise TimeoutError(
                        f"Escaneo superó el límite duro de {hard_timeout_s}s "
                        "(módulo bloqueado o latencia extrema)"
                    )
            finally:
                                                                                 
                _scan_ex.shutdown(wait=False, cancel_futures=True)

            eq.put({"type": "progress", "message": "Escaneo principal completado ✓ Recolectando reputación…", "percent": 95})

            def _do_reputation():
                try:
                    s = _req.Session()
                    s.verify = VERIFY_SSL
                    r = check_reputation(s, url, timeout=10)
                    s.close()
                    return r.to_dict()
                except Exception as e:
                    log.warning("Reputación: %s", e)
                    return {}

            def _do_subdomains():
                try:
                    s = _req.Session()
                    s.verify = VERIFY_SSL
                    r = enumerate_subdomains(s, url, timeout=8)
                    s.close()
                    return [sd.to_dict() for sd in r]
                except Exception as e:
                    log.warning("Subdominios: %s", e)
                    return []

            with _cf.ThreadPoolExecutor(max_workers=2) as _ex:
                _f_rep = _ex.submit(_do_reputation)
                _f_sub = _ex.submit(_do_subdomains)
                try:
                    result.reputation = _f_rep.result(timeout=15)
                except Exception as _re:
                    log.warning("Reputación timeout/error: %s", _re)
                    result.reputation = {}
                try:
                    result.subdomains = _f_sub.result(timeout=12)
                except Exception as _se:
                    log.warning("Subdominios timeout/error: %s", _se)
                    result.subdomains = []

            rd = result.to_dict()
                                                                             
            rd["scan_id"] = job_id
            rd["scanned_at"]     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            rd["legal_accepted"] = legal
            rd["ssl_unverified"] = not VERIFY_SSL                                               

                                                                               
            try:
                previous = get_latest_scan_same_url(rd.get("target_url", ""), exclude_scan_id=job_id)
                if previous:
                    from scanner.export import compare_scans
                    rd["scan_diff"] = {
                        "has_previous": True,
                        "previous_scan_id": previous.get("scan_id", ""),
                        "previous_scanned_at": previous.get("scanned_at", ""),
                        "diff": compare_scans(previous, rd),
                    }
                else:
                    rd["scan_diff"] = {"has_previous": False}
            except Exception as _diff_err:
                log.debug("scan_diff no disponible para %s: %s", job_id, _diff_err)

            try:
                save_scan(job_id, rd, legal, user_ip, job_status="done")
            except Exception as _dbe:
                log.error("save_scan falló para %s: %s", job_id, _dbe)

            with _jobs_lock:
                _jobs[job_id]["status"] = "done"
                _jobs[job_id]["result"] = rd

            try:
                upsert_job_state(
                    job_id,
                    url,
                    "done",
                    legal=legal,
                    user_ip=user_ip,
                    result=rd,
                )
            except Exception as e:
                log.warning("No se pudo persistir estado done %s: %s", job_id, e)

                                                                   
            try:
                from state import cache_set
                cache_set(url, rd)
            except Exception:
                pass

            eq.put({"type": "progress", "message": "Finalizando…", "percent": 99})
            eq.put({"type": "done", "result": rd})
            log.info("Escaneo completado: %s (%s) risk=%s", job_id, url, rd.get("risk_label"))

            threading.Thread(
                target=_pwa_cache_result,
                args=(url, job_id, json.dumps(rd)),
                daemon=True,
            ).start()

            if callback_url:
                threading.Thread(
                    target=_fire_webhook, args=(callback_url, rd), daemon=True
                ).start()

                                                                              
            def _fire_configured_webhooks():
                try:
                    from blueprints.webhooks import fire_webhooks
                    fire_webhooks(rd, job_id)
                except Exception as _we:
                    log.warning("Error disparando webhooks configurados: %s", _we)

            threading.Thread(target=_fire_configured_webhooks, daemon=True).start()

        except TimeoutError as te:
            debug_mode = state.DEBUG_MODE
            log.warning("Timeout en escaneo %s: %s", job_id, te)
            try:
                _partial = getattr(scanner, "_result", None)
                if _partial is not None:
                    _partial.finished_at = _partial.finished_at or time.time()
                    _partial.errors.append(
                        f"⚠ Escaneo interrumpido por timeout ({SCAN_TIMEOUT_S}s) — resultado parcial"
                    )
                    rd = _partial.to_dict()
                    rd["scanned_at"]     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    rd["legal_accepted"] = legal
                    rd["partial"]        = True
                    save_scan(job_id, rd, legal, user_ip, job_status="timeout")
                    with _jobs_lock:
                        _jobs[job_id]["status"] = "timeout"
                        _jobs[job_id]["result"] = rd
                        _jobs[job_id]["error_code"] = ErrorCode.SCAN_TIMEOUT.code_str
                    try:
                        upsert_job_state(
                            job_id,
                            url,
                            "timeout",
                            legal=legal,
                            user_ip=user_ip,
                            error=str(te),
                            result=rd,
                        )
                    except Exception as e:
                        log.warning("No se pudo persistir estado timeout %s: %s", job_id, e)
                    eq.put({
                        "type": "done",
                        "result": rd,
                        "partial": True,
                        "warning": str(te),
                        "error_code": ErrorCode.SCAN_TIMEOUT.code_str,
                    })
                    return
            except Exception as _save_err:
                log.warning("No se pudo guardar resultado parcial: %s", _save_err)
            
            error_obj = ScanError(
                ErrorCode.SCAN_TIMEOUT,
                job_id=job_id,
                url=url,
                timeout_seconds=SCAN_TIMEOUT_S,
                exception=str(te),
            )
            with _jobs_lock:
                _jobs[job_id]["status"] = "error"
                _jobs[job_id]["error"] = error_obj.message
                _jobs[job_id]["error_code"] = error_obj.code.code_str
            try:
                upsert_job_state(
                    job_id,
                    url,
                    "error",
                    legal=legal,
                    user_ip=user_ip,
                    error=error_obj.message,
                )
            except Exception as e:
                log.warning("No se pudo persistir estado error(timeout) %s: %s", job_id, e)
            eq.put({
                "type": "error",
                "message": error_obj.message,
                "error_code": error_obj.code.code_str,
                **(error_obj.to_dict(debug_mode=debug_mode).get("debug", {})),
            })

        except Exception as e:
            debug_mode = state.DEBUG_MODE
            log.error("Error en escaneo %s: %s", job_id, e, exc_info=True)
            error_obj = ScanError(
                ErrorCode.INTERNAL_ERROR,
                job_id=job_id,
                url=url,
                exception=str(e),
                exception_type=type(e).__name__,
            )
            with _jobs_lock:
                _jobs[job_id]["status"] = "error"
                _jobs[job_id]["error"] = error_obj.message
                _jobs[job_id]["error_code"] = error_obj.code.code_str
            try:
                upsert_job_state(
                    job_id,
                    url,
                    "error",
                    legal=legal,
                    user_ip=user_ip,
                    error=error_obj.message,
                )
            except Exception as e2:
                log.warning("No se pudo persistir estado error %s: %s", job_id, e2)
            eq.put({
                "type": "error",
                "message": error_obj.message,
                "error_code": error_obj.code.code_str,
                **(error_obj.to_dict(debug_mode=debug_mode).get("debug", {})),
            })

    finally:
        if acquired:
            _scan_semaphore.release()
            with _active_scans_lock:
                _active_scans_count = max(0, _active_scans_count - 1)

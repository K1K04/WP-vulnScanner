"""
WP VulnScanner — Scheduler de actualizaciones automáticas
=============================================================
Integrado en Flask, actualiza vulns.db en background sin intervención manual.
Usa APScheduler si está instalado, o un thread simple si no.

v5.3:
  - Ejecuta escaneos programados desde la tabla scheduled_scans (#1)
  - Envía notificaciones por email al terminar un escaneo programado (#2)
v6.0:
  - _UPDATE_STATUS: estado en tiempo real de actualizaciones de BD
  - Endpoint /api/db-update/status para polling del frontend
"""

from __future__ import annotations

import logging
import os
import smtplib
import sqlite3
import subprocess
import sys
import threading
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from state import DB_PATH as STATE_DB_PATH

try:
    from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
except ImportError:
    BackgroundScheduler = None
    CronTrigger = None
    SQLAlchemyJobStore = None

log = logging.getLogger("wpvulnscan.scheduler")

UPDATE_SCRIPT = Path(__file__).parent / "update_vulns.py"
DB_PATH       = Path(STATE_DB_PATH)

                                                                                
                                                
_UPDATE_STATUS: dict = {
    "running":    False,
    "source":     "",
    "started_at": "",
    "finished_at": "",
    "last_result": "",                        
    "last_message": "",
    "vulns_before": 0,
    "vulns_after":  0,
}
_UPDATE_LOCK = threading.Lock()


def get_update_status() -> dict:
    """Devuelve una copia del estado actual de actualización de BD."""
    with _UPDATE_LOCK:
        return dict(_UPDATE_STATUS)


def _run_update(source: str = "all"):
    """Ejecuta update_vulns.py en un subproceso separado con tracking de estado."""
                                                                      
                                                       
    from scanner.vulns_db import get_db_stats
    try:
        _vulns_before = get_db_stats().get("total_vulns", 0)
    except Exception:
        _vulns_before = 0

    with _UPDATE_LOCK:
        _UPDATE_STATUS["running"]      = True
        _UPDATE_STATUS["source"]       = source
        _UPDATE_STATUS["started_at"]   = datetime.now().isoformat()
        _UPDATE_STATUS["finished_at"]  = ""
        _UPDATE_STATUS["last_result"]  = ""
        _UPDATE_STATUS["last_message"] = f"Iniciando actualización desde '{source}'..."
        _UPDATE_STATUS["vulns_before"] = _vulns_before

    log.info("Scheduler: iniciando actualización de vulns.db (source=%s)", source)
    try:
                                                                           
        if not UPDATE_SCRIPT.is_file():
            raise FileNotFoundError(f"Script de actualización no encontrado: {UPDATE_SCRIPT}")
        result = subprocess.run(
            [sys.executable, str(UPDATE_SCRIPT), "--source", source],
            capture_output=True, text=True, timeout=3600,
            cwd=str(UPDATE_SCRIPT.parent),
        )
        if result.returncode == 0:
            log.info("Scheduler: actualización completada\n%s", result.stdout[-500:])
            msg = result.stdout.strip().split("\n")[-1][:200] if result.stdout.strip() else "Completada"
            try:
                vulns_after = get_db_stats().get("total_vulns", 0)
            except Exception:
                vulns_after = 0
            with _UPDATE_LOCK:
                _UPDATE_STATUS["last_result"]   = "ok"
                _UPDATE_STATUS["last_message"]  = msg
                _UPDATE_STATUS["vulns_after"]   = vulns_after
        else:
            err = result.stderr.strip()[-300:] if result.stderr.strip() else "Error desconocido"
            log.error("Scheduler: error en actualización:\n%s", err)
            with _UPDATE_LOCK:
                _UPDATE_STATUS["last_result"]  = "error"
                _UPDATE_STATUS["last_message"] = err
    except subprocess.TimeoutExpired:
        log.error("Scheduler: timeout en actualización (>1h)")
        with _UPDATE_LOCK:
            _UPDATE_STATUS["last_result"]  = "error"
            _UPDATE_STATUS["last_message"] = "Timeout — actualización superó 1 hora"
    except Exception as e:
        log.error("Scheduler: excepción: %s", e)
        with _UPDATE_LOCK:
            _UPDATE_STATUS["last_result"]  = "error"
            _UPDATE_STATUS["last_message"] = str(e)
    finally:
        with _UPDATE_LOCK:
            _UPDATE_STATUS["running"]     = False
            _UPDATE_STATUS["finished_at"] = datetime.now().isoformat()


def _run_update_thread(source: str = "all"):
    """Wrapper para ejecutar en thread background."""
    t = threading.Thread(target=_run_update, args=(source,), daemon=True, name="VulnsUpdater")
    t.start()
    return t


                                                                               

def send_scan_notification(to_email: str, url: str, scan_id: str,
                            risk_score: int, risk_label: str,
                            vuln_count: int) -> bool:
    """
    Envía un email de notificación al terminar un escaneo programado.
    Requiere variables SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS en .env.
    """
    smtp_host = os.environ.get("SMTP_HOST", "")
                                                                          
    try:
        smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    except (ValueError, TypeError):
        smtp_port = 587
        log.warning("SMTP_PORT inválido en .env — usando 587 por defecto")
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASS", "")
    from_addr = os.environ.get("SMTP_FROM", smtp_user)

    if not smtp_host or not to_email:
        log.debug("SMTP no configurado o email vacío — notificación omitida")
        return False

    RISK_EMOJI = {"CRÍTICO": "🔴", "ALTO": "🟠", "MEDIO": "🟡", "BAJO": "🟢"}
    emoji = RISK_EMOJI.get(risk_label, "⚪")

                                                                           
                                                                              
    import html as _html
    _url_esc   = _html.escape(str(url))
    _label_esc = _html.escape(str(risk_label))
    _id_esc    = _html.escape(str(scan_id))
    _emoji_esc = _html.escape(str(emoji))

    subject = f"{emoji} WPVulnScanner: {risk_label} en {url}"
    html_body = f"""
    <html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px">
    <h2 style="color:#39ff14">WP VulnScanner — Resultado de escaneo programado</h2>
      <table style="border-collapse:collapse;width:100%">
        <tr><td style="padding:8px;color:#8b949e">Objetivo</td>
            <td style="padding:8px"><a href="{_url_esc}" style="color:#00d4ff">{_url_esc}</a></td></tr>
        <tr style="background:#161b22">
            <td style="padding:8px;color:#8b949e">Riesgo</td>
            <td style="padding:8px;font-weight:bold;color:{'#ff4757' if risk_score>=70 else '#ff6b35' if risk_score>=45 else '#ffa502' if risk_score>=20 else '#2ed573'}">
              {_emoji_esc} {_label_esc} ({int(risk_score)}/100)</td></tr>
        <tr><td style="padding:8px;color:#8b949e">Vulnerabilidades</td>
            <td style="padding:8px;color:#{'ff4757' if vuln_count>0 else '2ed573'}">{int(vuln_count)}</td></tr>
        <tr style="background:#161b22">
            <td style="padding:8px;color:#8b949e">Scan ID</td>
            <td style="padding:8px;font-size:11px;color:#484f58">{_id_esc}</td></tr>
        <tr><td style="padding:8px;color:#8b949e">Fecha</td>
            <td style="padding:8px">{datetime.now().strftime('%d/%m/%Y %H:%M')}</td></tr>
      </table>
      <p style="margin-top:16px;font-size:11px;color:#484f58">
        Generado automáticamente por WP VulnScanner
      </p>
    </body></html>
    """

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = from_addr
        msg["To"]      = to_email
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        use_ssl_flag = os.environ.get("SMTP_USE_SSL", "").lower() in ("1", "true", "yes")
        try_ssl = smtp_port == 465 or use_ssl_flag

        if try_ssl:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15) as server:
                server.ehlo()
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.sendmail(from_addr, [to_email], msg.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                server.ehlo()
                                                                                           
                try:
                    server.starttls()
                    server.ehlo()
                except Exception:
                    log.debug("starttls no disponible o falló — continuando sin TLS")
                if smtp_user and smtp_pass:
                    try:
                        server.login(smtp_user, smtp_pass)
                    except Exception as _le:
                        log.warning("SMTP login falló: %s", _le)
                server.sendmail(from_addr, [to_email], msg.as_string())

        log.info("Notificación enviada a %s para %s (risk=%s)", to_email, url, risk_label)
        return True
    except Exception as e:
        log.warning("Error enviando email a %s: %s", to_email, e)
        return False


                                                                               

def _should_run(cron_expr: str, last_run: str | None) -> bool:
    """Determina si un escaneo programado debe ejecutarse ahora."""
    now = datetime.now()
    if not last_run:
        return True                                    
    try:
        last = datetime.fromisoformat(last_run)
    except Exception:
        return True

    if cron_expr == "daily":
        return (now - last) >= timedelta(days=1)
    elif cron_expr == "weekly":
        return (now - last) >= timedelta(weeks=1)
    elif cron_expr == "monthly":
        return (now - last) >= timedelta(days=30)
                                                                                    
    log.warning("_should_run: cron_expr desconocido '%s' — escaneo nunca se ejecutará", cron_expr)
    return False


def _run_scheduled_scans(app_instance=None):
    """
    Mejora #1: Lee scheduled_scans de la BD y lanza los que toca.
    Se llama periódicamente desde el scheduler (cada hora).
    Bug 4 fix: limita el número de escaneos programados lanzados por ciclo
    al mismo MAX_CONCURRENT de app.py para evitar efecto manada cuando
    el servidor lleva tiempo caído y hay muchos escaneos pendientes.
    Bug 7/8 fix: top-level try/except para que APScheduler no deje de llamar
    a esta función si ocurre un error inesperado en una iteración.
    """
    try:
        _run_scheduled_scans_impl(app_instance)
    except Exception as _sched_err:
        log.error("Scheduler: error inesperado en _run_scheduled_scans: %s", _sched_err, exc_info=True)


def _run_scheduled_scans_impl(app_instance=None):
    log.info("Scheduler: comprobando escaneos programados...")

                                                             
    try:
        from app import MAX_CONCURRENT as _MAX                
        _max_this_cycle = _MAX
    except Exception:
        _max_this_cycle = 3                        

    try:
        with sqlite3.connect(str(DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row
            schedules = conn.execute(
                "SELECT * FROM scheduled_scans WHERE active=1"
            ).fetchall()
    except Exception as e:
        log.error("Scheduler: error leyendo scheduled_scans: %s", e)
        return

    launched_this_cycle = 0
    for sched in schedules:
        sched = dict(sched)
        if not _should_run(sched["cron_expr"], sched.get("last_run")):
            continue

                                                                        
        if launched_this_cycle >= _max_this_cycle:
            log.warning(
                "Scheduler: límite de %d escaneos por ciclo alcanzado — "
                "%d pendientes se procesarán en el siguiente ciclo",
                _max_this_cycle,
                sum(1 for s in schedules if _should_run(dict(s).get("cron_expr",""), dict(s).get("last_run")))
            )
            break

        url          = sched["url"]
        notify_email = sched.get("notify_email", "")
        callback_url = sched.get("callback_url", "")
        sched_id     = sched["id"]

                                                                        
                                                                             
        try:
            with sqlite3.connect(str(DB_PATH)) as c_guard:
                c_guard.execute(
                    "UPDATE scheduled_scans SET last_run=? WHERE id=?",
                    (datetime.now().isoformat(), sched_id)
                )
                c_guard.commit()
        except Exception as eg:
            log.warning("Scheduler: no se pudo marcar last_run antes de lanzar %s: %s", sched_id, eg)

        log.info("Scheduler: lanzando escaneo programado %s → %s", sched_id, url)

                                                                   
        try:
            import uuid, queue
            from app import _jobs, _jobs_lock, _run_scan                

            job_id = str(uuid.uuid4()).replace("-", "")[:12]                                
            with _jobs_lock:
                _jobs[job_id] = {
                    "status": "running", "url": url,
                    "started": __import__("time").time(), "result": None,
                    "queue": queue.Queue(),
                }

                                                         
            effective_callback = callback_url

            def _scan_and_notify(jid, u, ce, ni, _sid=sched_id):                                  
                """Wrapper que lanza el escaneo y envía email al terminar.
                BUG-4 FIX: captura el resultado directo de la queue en vez de
                hacer polling de _jobs (que puede ser purgado por _cleanup_jobs
                antes de que el bucle lo lea, perdiendo la notificación).
                """
                import time as _t
                from app import _jobs as _j_dict, _jobs_lock as _jl                
                import queue as _q_mod

                                                                       
                with _jl:
                    _job_queue = _j_dict.get(jid, {}).get("queue")

                _run_scan(jid, u, True, "scheduler", ce)

                                                                                           
                final_status = "error"
                final_result = {}
                                                                             
                                                                                         
                try:
                    from app import SCAN_TIMEOUT_S as _sto                
                    _max_wait = _sto + 60
                except Exception:
                    _max_wait = 360                   
                _max_iters = max(60, _max_wait)

                if _job_queue:
                    try:
                        for _ in range(_max_iters):
                            try:
                                event = _job_queue.get(timeout=1)
                                if event.get("type") == "done":
                                    final_status = "done"
                                    final_result = event.get("result", {})
                                    break
                                elif event.get("type") == "error":
                                    final_status = "error"
                                    break
                            except _q_mod.Empty:
                                pass
                    except Exception as _e:
                        log.debug("scheduler queue loop suppressed: %s", _e)
                else:
                                                                                  
                    for _ in range(_max_iters):
                        _t.sleep(1)
                        with _jl:
                            job = _j_dict.get(jid, {})
                        st = job.get("status")
                        if st == "done":
                            final_status = "done"
                            final_result = job.get("result", {})
                            break
                        elif st == "error":
                            break

                if ni:
                    if final_status == "done":
                        send_scan_notification(
                            ni, u, jid,
                            final_result.get("risk_score", 0),
                            final_result.get("risk_label", "?"),
                            final_result.get("summary", {}).get("vulns_found", 0),
                        )
                    else:
                        send_scan_notification(ni, u, jid, 0, "ERROR", 0)

                                           
                                                                                     
                try:
                    with sqlite3.connect(str(DB_PATH)) as c2:
                        c2.execute(
                            "UPDATE scheduled_scans SET last_run=?, last_scan_id=? WHERE id=?",
                            (datetime.now().isoformat(), jid, _sid)
                        )
                        c2.commit()
                except Exception as ex:
                    log.warning("Scheduler: error actualizando last_run: %s", ex)

                                                                                          
                try:
                    with _jl:
                        _j_dict.pop(jid, None)
                except Exception:
                    pass

            t = threading.Thread(
                target=_scan_and_notify,
                args=(job_id, url, effective_callback, notify_email),
                daemon=True,
                name=f"ScheduledScan-{sched_id}",
            )
            t.start()
            launched_this_cycle += 1

        except Exception as e:
            log.error("Scheduler: error lanzando escaneo %s: %s", sched_id, e)


                                                                             
                                                                      
                                                                                      

def _update_wordfence():
    """Job: actualizar Wordfence Intelligence"""
    _run_update_thread("wordfence")

def _update_nvd():
    """Job: actualizar NVD"""
    _run_update_thread("nvd")

def _update_patchstack():
    """Job: actualizar Patchstack"""
    _run_update_thread("patchstack")

def _update_github():
    """Job: actualizar GitHub Advisory"""
    _run_update_thread("github")

def _update_wpscan():
    """Job: actualizar WPScan API"""
    _run_update_thread("wpscan")


def start_scheduler(app=None):
    """
    Arranca el scheduler de actualizaciones.
    Intenta APScheduler primero; si no está, usa un timer simple.

    Schedule por defecto:
      - Cada lunes a las 03:00 → todas las fuentes (NVD, Patchstack, GitHub, Offline)
      - Si hay WPSCAN_API_TOKEN → también WPScan API
      - Al arrancar → si la BD lleva más de 7 días sin actualizar, actualiza ahora
    """
    from scanner.vulns_db import get_db_freshness, init_vulns_db

                              
    init_vulns_db()

                                  
    freshness = get_db_freshness()
    if not freshness.get("fresh", True):
        days_old = freshness.get("days_old", 0)
        log.warning("vulns.db lleva %d días sin actualizar — actualizando en background...", days_old)
        _run_update_thread("all")
    else:
        log.info("vulns.db al día (última update: %s)", freshness.get("last_update","?"))

                          
    if BackgroundScheduler is None or CronTrigger is None:
        log.info("APScheduler no instalado — usando timer simple (actualización cada 7 días)")
        _start_simple_timer()
        return None

    try:
                                                                              
                                                                        
                                                                   
        jobstores = {}
        try:
            if SQLAlchemyJobStore is not None:
                _jobs_db_url = f"sqlite:///{STATE_DB_PATH}"
                jobstores["default"] = SQLAlchemyJobStore(url=_jobs_db_url)
                log.info("Scheduler: jobstore SQLite activado (%s)", STATE_DB_PATH)
            else:
                raise ImportError("SQLAlchemyJobStore no disponible")
        except Exception as _jse:
            log.info("Scheduler: jobstore SQLite no disponible (%s) — usando memoria", _jse)

        scheduler = BackgroundScheduler(daemon=True, jobstores=jobstores)

                                                                              
                                                                         
                                                                           
                                                                           
                                                                      
        GRACE_S = 3600                                                         

                                                                  
                                                                                              
        scheduler.add_job(
            func=_update_wordfence,
            trigger=CronTrigger(hour=2, minute=0),                              
            id="daily_wordfence",
            name="Actualización diaria Wordfence Intelligence",
            replace_existing=True,
            misfire_grace_time=GRACE_S,
        )
                                                                       
        scheduler.add_job(
            func=_update_nvd,
            trigger=CronTrigger(day_of_week="mon", hour=3, minute=0),
            id="weekly_nvd", name="Actualización semanal NVD",
            replace_existing=True,
            misfire_grace_time=GRACE_S,
        )
        scheduler.add_job(
            func=_update_patchstack,
            trigger=CronTrigger(day_of_week="mon", hour=3, minute=15),
            id="weekly_patchstack", name="Actualización semanal Patchstack",
            replace_existing=True,
            misfire_grace_time=GRACE_S,
        )
        scheduler.add_job(
            func=_update_github,
            trigger=CronTrigger(day_of_week="mon", hour=3, minute=30),
            id="weekly_github", name="Actualización semanal GitHub Advisory",
            replace_existing=True,
            misfire_grace_time=GRACE_S,
        )
                                                                
        scheduler.add_job(
            func=_run_scheduled_scans,
            trigger="interval", hours=1,
            id="check_scheduled_scans",
            name="Ejecución de escaneos programados",
            replace_existing=True,
            misfire_grace_time=GRACE_S,
        )

                                              
        if os.environ.get("WPSCAN_API_TOKEN"):
            scheduler.add_job(
                func=_update_wpscan,
                trigger=CronTrigger(day_of_week="wed", hour=4, minute=0),
                id="weekly_wpscan",
                name="Actualización semanal WPScan API",
                replace_existing=True,
                misfire_grace_time=GRACE_S,
            )
            log.info("Scheduler: WPScan API programada los miércoles a las 04:00")

        scheduler.start()
        log.info("APScheduler iniciado. Próxima actualización: lunes 03:00")

        if app:
                                                  
            app.config["SCHEDULER"] = scheduler

        return scheduler

    except Exception as _scheduler_exc:
        log.error("Scheduler: error inicializando APScheduler: %s", _scheduler_exc, exc_info=True)
        _start_simple_timer()
        return None


def _start_simple_timer():
    """Timer simple: actualiza Wordfence Intelligence cada 24h y otras fuentes semanalmente."""
    import time as _time

    def _check_loop():
        _hour_counter = 0
        while True:
            _time.sleep(3600)                       
            _hour_counter += 1
            try:
                                                                     
                                                                              
                _run_scheduled_scans()

                                                                               
                if _hour_counter % 24 == 2:                     
                    log.info("Timer: actualizando Wordfence Intelligence (diario)...")
                    _run_update_thread("wordfence")

                                                                           
                if _hour_counter % 168 == 72:                         
                    log.info("Timer: actualización semanal NVD + Patchstack + GitHub...")
                    _run_update_thread("nvd")
                    _time.sleep(300)
                    _run_update_thread("patchstack")
                    _time.sleep(300)
                    _run_update_thread("github")

            except Exception as e:
                log.error("Timer: error en actualización programada: %s", e)

    t = threading.Thread(target=_check_loop, daemon=True, name="VulnsUpdateTimer")
    t.start()
    log.info("Simple update timer iniciado — Wordfence diario, resto semanal")


def get_scheduler_status(app=None) -> dict:
    """Estado del scheduler para el dashboard."""
    from scanner.vulns_db import get_db_stats, get_db_freshness

    stats     = get_db_stats()
    freshness = get_db_freshness()

    next_run = None
    jobs     = []
    try:
        if app and app.config.get("SCHEDULER"):
            sched = app.config["SCHEDULER"]
            for job in sched.get_jobs():
                next_fire = job.next_run_time
                jobs.append({
                    "id":       job.id,
                    "name":     job.name,
                    "next_run": str(next_fire) if next_fire else None,
                })
            if jobs:
                next_run = min((j["next_run"] for j in jobs if j["next_run"]), default=None)
    except Exception as _e:
        log.debug("non-critical path suppressed: %s", _e)

                                                        
    by_sev = {}
    for row in (stats.get("by_severity") or []):
        try:
            by_sev[row["severity"]] = row["cnt"]
        except Exception:
            pass
    critical_count  = stats.get("critical", by_sev.get("critical", 0))
    high_count      = by_sev.get("high", 0)
    medium_count    = by_sev.get("medium", 0)
    days_old        = freshness.get("days_old", 0)
    last_update_str = freshness.get("last_update") or stats.get("last_update") or ""

    return {
                                                                            
        "db_total_vulns":  stats["total_vulns"],
        "db_components":   stats["components"],
        "db_last_update":  stats["last_update"],
        "db_days_old":     days_old,
        "db_fresh":        freshness.get("fresh", False),
        "db_sources":      stats["by_source"],
        "scheduler_jobs":  jobs,
        "next_run":        next_run,
                                                                            
        "vuln_count":       stats["total_vulns"],
        "critical_count":   critical_count,
        "high_count":       high_count,
        "medium_count":     medium_count,
        "plugin_count":     stats["components"],
        "days_since_update": days_old,
        "last_update":       last_update_str,
                                                                            
        "fresh":    freshness.get("fresh", False),
        "days_old": days_old,
    }
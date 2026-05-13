"""
blueprints/scan.py — Rutas de escaneo de WP VulnScanner
============================================================
Rutas:
  POST /scan                      — inicia un escaneo (UI)
  GET  /scan/<id>/stream          — SSE de progreso
  GET  /scan/<id>/result          — resultado JSON
  GET  /scan/<id>/pdf             — descarga PDF
  GET  /scan/<id>/executive-pdf   — PDF ejecutivo
  GET  /scan/<id>/csv             — descarga CSV
  GET  /scan/<id>/excel           — descarga Excel
  GET  /scan/<id>/json            — descarga JSON estructurado
  GET  /scan/<id>/html            — descarga HTML standalone
  POST /scan/<id>/active          — análisis activo
  GET  /r/<id>                    — permalink corto
  GET  /attack-map/<id>           — mapa de ataque
  POST /api/scan                  — API REST asíncrona
  POST /api/bulk                  — escaneos en bulk
  POST /api/rescan                — reescaneo
  GET|POST /api/quick-scan        — escaneo rápido CI/CD
"""

from __future__ import annotations

import io
import json
import logging
import queue
import threading
import time
import uuid
from datetime import datetime, timezone

from flask import (Blueprint, Response, jsonify, render_template,
                   request, send_file, stream_with_context)

from db import get_job_state, get_scan_from_db, normalize_scan_result, upsert_job_state
from scan_engine import _run_scan
from state import (
    API_KEY, VERIFY_SSL, SCAN_TIMEOUT_S, MAX_CONCURRENT, DB_PATH,
    _active_scans_count, _active_scans_lock, _jobs, _jobs_lock,
    _validate_job_id, normalize_url, is_safe_url, _get_client_ip,
    rate_limit, require_api_key, SCAN_RATE_LIMIT, API_RATE_LIMIT,
    cache_get, cache_invalidate,
)

log = logging.getLogger("wpvulnscan.scan")

scan_bp = Blueprint("scan", __name__)


def _new_job(url: str, legal: bool = False, user_ip: str = "unknown") -> tuple[str, dict]:
    """Crea un nuevo job en memoria y devuelve (job_id, entry)."""
    job_id = str(uuid.uuid4()).replace("-", "")[:12]
    entry  = {
        "status":  "running",
        "url":     url,
        "started": time.time(),
        "result":  None,
        "queue":   queue.Queue(),
    }
    with _jobs_lock:
        _jobs[job_id] = entry
    try:
        upsert_job_state(
            job_id,
            url,
            "running",
            legal=legal,
            user_ip=user_ip,
            started_ts=entry["started"],
        )
    except Exception as e:
        log.warning("No se pudo persistir job running %s: %s", job_id, e)
    return job_id, entry


def _find_running_job_same_target(url: str, user_ip: str, max_age_s: int = 180) -> str:
    """Busca un job running en memoria para la misma URL/IP para evitar duplicados."""
    now = time.time()
    with _jobs_lock:
        for jid, job in _jobs.items():
            try:
                if job.get("status") != "running":
                    continue
                if (job.get("url") or "") != url:
                    continue
                started = float(job.get("started") or now)
                if (now - started) > max_age_s:
                    continue
                return jid
            except Exception:
                continue
    return ""


                                                                               
         
                                                                               

@scan_bp.route("/scan", methods=["POST"])
@rate_limit(SCAN_RATE_LIMIT)
def start_scan():
    data         = request.get_json(silent=True) or request.form
    url          = normalize_url((data.get("url") or "").strip())
    legal        = bool(data.get("legal_accepted"))
    user_ip      = request.remote_addr or "unknown"
    callback_url = (data.get("callback_url") or "").strip()

    if not url:
        return jsonify({"error": "URL requerida"}), 400
    if not legal:
        return jsonify({"error": "Debes confirmar que tienes autorización para escanear este sitio"}), 403

    safe, reason = is_safe_url(url)
    if not safe:
        log.warning("URL bloqueada (SSRF): %s — %s (IP: %s)", url, reason, user_ip)
        return jsonify({"error": f"URL no permitida: {reason}"}), 400

    running_same = _find_running_job_same_target(url, user_ip, max_age_s=180)
    if running_same:
        log.info("Escaneo duplicado evitado: %s → reutilizando %s (IP: %s)", url, running_same, user_ip)
        return jsonify({
            "job_id": running_same,
            "deduped": True,
            "status": "running",
            "slots_remaining": 0,
        })

                                                                               
    force_rescan = bool(data.get("force_rescan"))
    if not force_rescan:
        cached = cache_get(url)
        if cached:
            job_id, _ = _new_job(url, legal=legal, user_ip=user_ip)
            with _jobs_lock:
                _jobs[job_id]["status"] = "done"
                _jobs[job_id]["result"] = cached
            try:
                upsert_job_state(job_id, url, "done", legal=legal, user_ip=user_ip, result=cached)
            except Exception as e:
                log.warning("No se pudo persistir job cache-hit %s: %s", job_id, e)
            log.info("Cache hit: %s → job %s (IP: %s)", url, job_id, user_ip)
            return jsonify({"job_id": job_id, "cached": True, "slots_remaining": 0})

    if callback_url:
        cb_safe, cb_reason = is_safe_url(callback_url)
        if not cb_safe:
            return jsonify({"error": f"callback_url no válida: {cb_reason}"}), 400

    with _active_scans_lock:
        slots_left = MAX_CONCURRENT - _active_scans_count
    if slots_left == 0:
        return jsonify({"error": f"Servidor al límite ({MAX_CONCURRENT} escaneos simultáneos). Reintenta en un momento."}), 503

    job_id, _ = _new_job(url, legal=legal, user_ip=user_ip)
    log.info("Escaneo iniciado: %s → %s (IP: %s)", job_id, url, user_ip)
    threading.Thread(target=_run_scan, args=(job_id, url, legal, user_ip, callback_url), daemon=True).start()
    return jsonify({"job_id": job_id, "slots_remaining": max(0, slots_left - 1)})


@scan_bp.route("/scan/<job_id>/stream")
def scan_stream(job_id: str):
    if not _validate_job_id(job_id):
        return jsonify({"error": "job_id inválido"}), 400
    with _jobs_lock:
        in_mem = job_id in _jobs
    if not in_mem:
        js = get_job_state(job_id)
        if js and js.get("status") == "running":
            return jsonify({
                "error": "Job en ejecución, pero stream SSE no disponible tras reinicio. Consulta /scan/<id>/result.",
            }), 409
        return jsonify({"error": "Job no encontrado"}), 404

    def generate():
        with _jobs_lock:
            job_entry = _jobs.get(job_id)
        if job_entry is None:
            yield f"data: {json.dumps({'type':'error','message':'Job no encontrado'})}\n\n"
            return
        eq: queue.Queue = job_entry["queue"]
        deadline = time.time() + SCAN_TIMEOUT_S + 120
        try:
            while time.time() < deadline:
                try:
                                                                                      
                    yield "retry: 5000\n\n"

                    event = eq.get(timeout=10)
                    yield f"data: {json.dumps(event)}\n\n"
                    if event["type"] in ("done", "error"):
                        break
                except queue.Empty:
                    yield f"data: {json.dumps({'type':'heartbeat'})}\n\n"
            else:
                yield f"data: {json.dumps({'type':'error','message':'Stream timeout'})}\n\n"
        except GeneratorExit:
            pass

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",                                      
            "X-Content-Type-Options": "nosniff",
        },
    )


@scan_bp.route("/scan/<job_id>/result")
def get_result(job_id: str):
    if not _validate_job_id(job_id):
        return jsonify({"error": "job_id inválido"}), 400
    with _jobs_lock:
        job = _jobs.get(job_id)
    if job is not None:
        if job["status"] == "running":
            return jsonify({"status": "running"}), 202
        if job["status"] == "error":
            return jsonify({"status": "error", "message": job.get("error")}), 500
        return jsonify({"status": "done", "result": normalize_scan_result(job["result"], scan_id=job_id)})

                                                                 
    job_state = get_job_state(job_id)
    if job_state:
        st = (job_state.get("status") or "").lower().strip()
        if st == "running":
            return jsonify({"status": "running"}), 202
        if st == "error":
            return jsonify({"status": "error", "message": job_state.get("error") or "Error"}), 500
        if st in ("done", "timeout") and job_state.get("result") is not None:
            return jsonify({"status": "done", "result": normalize_scan_result(job_state["result"], scan_id=job_id)})

    result = get_scan_from_db(job_id)
    if result:
        return jsonify({"status": "done", "result": normalize_scan_result(result, scan_id=job_id)})
    return jsonify({"error": "Job no encontrado"}), 404


                                                                               
         
                                                                               

def _resolve_result(job_id: str):
    """Helper: obtiene resultado desde jobs en memoria o BD."""
    result = None
    with _jobs_lock:
        entry = _jobs.get(job_id)
        if entry and entry.get("result"):
            result = normalize_scan_result(entry["result"], scan_id=job_id)
    if result is None:
        js = get_job_state(job_id)
        if js and js.get("result") is not None:
            result = normalize_scan_result(js.get("result"), scan_id=job_id)
    if result is None:
        result = get_scan_from_db(job_id)
    return result


@scan_bp.route("/scan/<job_id>/pdf")
def download_pdf(job_id: str):
    if not _validate_job_id(job_id):
        return jsonify({"error": "job_id inválido"}), 400
    result = _resolve_result(job_id)
    if not result:
        return jsonify({"error": "Escaneo no encontrado"}), 404
    try:
        from pdf_gen import generate_pdf
        pdf_bytes = generate_pdf(result)
        domain = result.get("target_url", "").split("//")[-1].split("/")[0]
        fname  = f"wpvuln-{domain}-{job_id[:6]}.pdf"
        return send_file(io.BytesIO(pdf_bytes), mimetype="application/pdf",
                         as_attachment=True, download_name=fname)
    except Exception as e:
        log.error("Error generando PDF %s: %s", job_id, e, exc_info=True)
        return jsonify({"error": f"Error generando PDF: {e}"}), 500


@scan_bp.route("/scan/<job_id>/executive-pdf")
def download_executive_pdf(job_id: str):
    if not _validate_job_id(job_id):
        return jsonify({"error": "job_id inválido"}), 400
    result = _resolve_result(job_id)
    if not result:
        return jsonify({"error": "Escaneo no encontrado"}), 404
    try:
        from scanner.export import generate_executive_pdf
        pdf_bytes = generate_executive_pdf(result)
        domain = result.get("target_url", "").split("//")[-1].split("/")[0]
        fname  = f"ejecutivo-{domain}-{job_id[:6]}.pdf"
        return send_file(io.BytesIO(pdf_bytes), mimetype="application/pdf",
                         as_attachment=True, download_name=fname)
    except Exception as e:
        log.error("Error generando PDF ejecutivo %s: %s", job_id, e, exc_info=True)
        return jsonify({"error": f"Error generando PDF ejecutivo: {e}"}), 500


def _csv_safe(v) -> str:
    """Neutraliza CSV formula injection."""
    s = str(v) if v is not None else ""
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + s
    return s


@scan_bp.route("/scan/<job_id>/csv")
def export_csv(job_id: str):
    if not _validate_job_id(job_id):
        return jsonify({"error": "job_id inválido"}), 400
    rd = _resolve_result(job_id)
    if not rd:
        return jsonify({"error": "Resultado no encontrado"}), 404

    import csv
    out = io.StringIO()
    w   = csv.writer(out)

    w.writerow(["Campo", "Valor"])
    w.writerow(["URL",           _csv_safe(rd.get("target_url", ""))])
    w.writerow(["Fecha",         rd.get("scanned_at", "")])
    w.writerow(["Duración (s)",  rd.get("duration", "")])
    w.writerow(["Risk Score",    rd.get("risk_score", "")])
    w.writerow(["Risk Label",    rd.get("risk_label", "")])
    w.writerow(["WP Version",    rd.get("wp_version", "")])
    s = rd.get("summary", {})
    w.writerow(["Vulnerabilidades",   s.get("vulns_found", 0)])
    w.writerow(["Críticas",           s.get("critical_vulns", 0)])
    w.writerow(["Altas",              s.get("high_vulns", 0)])
    w.writerow(["Plugins detectados", s.get("plugins_found", 0)])
    w.writerow(["Archivos expuestos", s.get("exposed_files", 0)])
    w.writerow(["Usuarios",           s.get("users_found", 0)])
    w.writerow([])

    for plugin in rd.get("plugins", []):
        if not w.dialect:
            w.writerow(["── PLUGINS ──"])
            w.writerow(["Slug", "Versión", "Desactualizado", "Tipo"])
        w.writerow([_csv_safe(plugin.get("slug", "")), plugin.get("version", ""),
                    "Sí" if plugin.get("is_outdated") else "No", plugin.get("type", "plugin")])

    if rd.get("plugins"):
        w.writerow([])

    all_vulns = rd.get("vulnerabilities", [])
    if all_vulns:
        w.writerow(["── VULNERABILIDADES ──"])
        w.writerow(["CVE/ID", "Componente", "Título", "Severidad", "CVSS", "Fixed In"])
        for v in all_vulns:
            w.writerow([v.get("cve_id") or v.get("cve") or "",
                        v.get("plugin_slug") or v.get("component", ""),
                        _csv_safe(v.get("title", "")), v.get("severity", ""),
                        v.get("cvss_score") or v.get("cvss", ""),
                        v.get("fixed_in", "")])
        w.writerow([])

    exposed = rd.get("exposed_files", [])
    if exposed:
        w.writerow(["── ARCHIVOS EXPUESTOS ──"])
        w.writerow(["Ruta", "URL", "Severidad", "Nota"])
        for f in exposed:
            w.writerow([_csv_safe(f.get("path", "")), f.get("url", ""),
                        f.get("severity", ""), f.get("note", "")])
        w.writerow([])

    users = rd.get("users", [])
    if users:
        w.writerow(["── USUARIOS ──"])
        w.writerow(["ID", "Login", "Nombre", "Método"])
        for u in users:
            w.writerow([u.get("id", ""), _csv_safe(u.get("login", "")),
                        _csv_safe(u.get("name", "")), u.get("method", "")])

    csv_bytes = out.getvalue().encode("utf-8-sig")
    domain    = rd.get("target_url", "site").replace("https://", "").replace("http://", "").split("/")[0]
    filename  = f"wpvuln_{domain}_{job_id[:8]}.csv"
    return Response(csv_bytes, mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@scan_bp.route("/scan/<job_id>/excel")
def download_excel(job_id: str):
    if not _validate_job_id(job_id):
        return jsonify({"error": "job_id inválido"}), 400
    result = _resolve_result(job_id)
    if not result:
        return jsonify({"error": "Escaneo no encontrado"}), 404
    try:
        from scanner.export import generate_excel
        xlsx_bytes = generate_excel(result)
        domain = result.get("target_url", "").split("//")[-1].split("/")[0]
        fname  = f"wpvuln-{domain}-{job_id[:6]}.xlsx"
        return send_file(
            io.BytesIO(xlsx_bytes),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True, download_name=fname,
        )
    except ImportError:
        return jsonify({"error": "Instala openpyxl: pip install openpyxl"}), 500
    except Exception as e:
        log.error("Error generando Excel %s: %s", job_id, e, exc_info=True)
        return jsonify({"error": f"Error generando Excel: {e}"}), 500


@scan_bp.route("/scan/<job_id>/json")
def download_json(job_id: str):
    if not _validate_job_id(job_id):
        return jsonify({"error": "job_id inválido"}), 400
    result = _resolve_result(job_id)
    if not result:
        return jsonify({"error": "Escaneo no encontrado"}), 404

    export = {
        "schema_version": "1.0",
        "generator":      "WP VulnScanner v6.1",
        "exported_at":    datetime.now().isoformat(),
        "scan": {
            "id":             job_id,
            "target_url":     result.get("target_url"),
            "scanned_at":     result.get("scanned_at"),
            "duration_s":     result.get("duration"),
            "risk":           {"score": result.get("risk_score"), "label": result.get("risk_label")},
            "summary":        result.get("summary", {}),
            "is_wordpress":   result.get("is_wordpress"),
            "wp_version":     result.get("wp_version"),
            "wp_outdated":    result.get("wp_outdated"),
            "php_version":    result.get("php_version"),
            "server_info":    result.get("server_info"),
            "xmlrpc_enabled": result.get("xmlrpc_enabled"),
            "login_exposed":  result.get("login_exposed"),
            "waf_detected":   result.get("waf_detected", []),
        },
        "vulnerabilities": result.get("vulnerabilities", []),
        "plugins":         result.get("plugins", []),
        "themes":          result.get("themes", []),
        "exposed_files":   result.get("exposed_files", []),
        "users":           result.get("users", []),
        "headers":         {"issues": result.get("headers_issues", []), "ok": result.get("headers_ok", [])},
        "ssl":             result.get("ssl_info"),
        "malware":         result.get("malware_indicators", []),
        "reputation":      result.get("reputation"),
    }

    from flask import current_app
    domain = (result.get("target_url") or "").split("//")[-1].split("/")[0]
    fname  = f"wpvuln-{domain}-{job_id[:6]}.json"
    resp   = current_app.response_class(
        response=json.dumps(export, ensure_ascii=False, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
    return resp


@scan_bp.route("/scan/<job_id>/html")
def download_html(job_id: str):
    if not _validate_job_id(job_id):
        return jsonify({"error": "job_id inválido"}), 400
    result = _resolve_result(job_id)
    if not result:
        return jsonify({"error": "Escaneo no encontrado"}), 404
    from scanner.export import generate_standalone_html
    try:
        html_bytes = generate_standalone_html(result)
    except Exception as e:
        log.error("Error generando HTML standalone: %s", e, exc_info=True)
        return jsonify({"error": f"Error generando HTML: {e}"}), 500
    domain = (result.get("target_url") or "").split("//")[-1].split("/")[0]
    fname  = f"wpvuln-{domain}-{job_id[:6]}.html"
    return Response(html_bytes, mimetype="text/html",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@scan_bp.route("/scan/<job_id>/markdown")
def download_markdown(job_id: str):
    if not _validate_job_id(job_id):
        return jsonify({"error": "job_id inválido"}), 400
    result = _resolve_result(job_id)
    if not result:
        return jsonify({"error": "Escaneo no encontrado"}), 404
    try:
        from scanner.export import generate_markdown
        md_bytes = generate_markdown(result)
        domain = (result.get("target_url") or "").split("//")[-1].split("/")[0]
        fname  = f"wpvuln-{domain}-{job_id[:6]}.md"
        return Response(md_bytes, mimetype="text/markdown",
                        headers={"Content-Disposition": f'attachment; filename="{fname}"'})
    except Exception as e:
        log.error("Error generando Markdown: %s", e, exc_info=True)
        return jsonify({"error": f"Error generando Markdown: {e}"}), 500


@scan_bp.route("/scan/<job_id>/sarif")
def download_sarif(job_id: str):
    if not _validate_job_id(job_id):
        return jsonify({"error": "job_id inválido"}), 400
    result = _resolve_result(job_id)
    if not result:
        return jsonify({"error": "Escaneo no encontrado"}), 404
    try:
        from scanner.export import generate_sarif
        sarif_bytes = generate_sarif(result)
        domain = (result.get("target_url") or "").split("//")[-1].split("/")[0]
        fname  = f"wpvuln-{domain}-{job_id[:6]}.sarif"
        return Response(sarif_bytes, mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{fname}"'})
    except Exception as e:
        log.error("Error generando SARIF: %s", e, exc_info=True)
        return jsonify({"error": f"Error generando SARIF: {e}"}), 500


                                                                               
                          
                                                                               

@scan_bp.route("/scan/<job_id>/ai-plan", methods=["POST"])
@require_api_key
def save_ai_plan(job_id: str):
    """Guarda el texto del plan IA en el resultado del job para incluirlo en PDFs."""
    if not _validate_job_id(job_id):
        return jsonify({"error": "job_id inválido"}), 400
    data = request.get_json(silent=True) or {}
    plan_text = (data.get("ai_plan") or "").strip()
    if not plan_text:
        return jsonify({"error": "ai_plan requerido"}), 400
    if len(plan_text) > 50_000:
        return jsonify({"error": "Texto demasiado largo"}), 400
                        
    with _jobs_lock:
        if job_id in _jobs and _jobs[job_id].get("result"):
            _jobs[job_id]["result"]["ai_plan"] = plan_text
                                        
    try:
        result = _resolve_result(job_id)
        if result:
            url = result.get("target_url", "") or result.get("url", "")
            if url:
                result["ai_plan"] = plan_text
                from state import cache_set
                cache_set(url, result)
    except Exception as _e:
        try:
            log.debug("ai_plan cache_set suppressed: %s", _e)
        except Exception:
            pass
    return jsonify({"ok": True})


@scan_bp.route("/scan/<job_id>/active", methods=["POST"])
@rate_limit(2)
def run_active_scan(job_id: str):
    if not _validate_job_id(job_id):
        return jsonify({"error": "job_id inválido"}), 400
    result = get_scan_from_db(job_id)
    if not result:
        with _jobs_lock:
            if job_id in _jobs and _jobs[job_id].get("result"):
                result = _jobs[job_id]["result"]
        if not result:
            return jsonify({"error": "Escaneo base no encontrado"}), 404

    data  = request.get_json(silent=True) or {}
    legal = data.get("legal_accepted", False)
    if not legal:
        return jsonify({"error": "Debes confirmar autorización para análisis activo"}), 403

    options  = data.get("options", {})
    user_ip  = request.remote_addr or "unknown"
    target   = result.get("target_url", "")

    import sqlite3 as _sq
    active_audit_id = str(uuid.uuid4()).replace("-", "")[:12]
    started_at      = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    modules_run     = json.dumps({
        "deep_enum":      options.get("deep_enum", True),
        "hidden_plugins": options.get("hidden_plugins", True),
        "backups":        options.get("backups", True),
        "injections":     options.get("injections", False),
        "bruteforce_removed": True,
    })
    try:
        audit_conn = _sq.connect(DB_PATH)
        try:
            audit_conn.execute("""
                INSERT INTO active_scans
                    (id, scan_id, started_at, user_ip, target_url, modules_run)
                VALUES (?,?,?,?,?,?)
            """, (active_audit_id, job_id, started_at, user_ip, target, modules_run))
            audit_conn.commit()
        finally:
            audit_conn.close()
    except Exception as audit_err:
        log.warning("No se pudo crear registro de auditoría activo: %s", audit_err)

    try:
        import requests as req
        import urllib3; urllib3.disable_warnings()
        from scanner.active import ActiveScanner

        session = req.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; WPVulnScanner/6.0)"})
        session.verify = VERIFY_SSL

        try:
            scanner      = ActiveScanner(session=session, base_url=target, timeout=10,
                                         known_plugins=result.get("plugins", []),
                                         known_users=result.get("users", []))
            active_result = scanner.run(
                do_deep_enum=options.get("deep_enum", True),
                do_hidden_plugins=options.get("hidden_plugins", True),
                do_backups=options.get("backups", True),
                do_injections=options.get("injections", False),
            )
        finally:
            try:
                session.close()
            except Exception:
                pass

        ar  = active_result.to_dict()
        summary = json.dumps({
            "waf":           ar.get("waf_detected", ""),
            "users_found":   len(ar.get("deep_users", [])),
            "hidden_plugins":len(ar.get("hidden_plugins", [])),
            "backup_files":  len(ar.get("backup_files", [])),
            "injections":    len(ar.get("injection_findings", [])),
            "bruteforce_removed": True,
        })
        try:
            from state import DB_PATH as _DB
            ac2 = _sq.connect(_DB)
            try:
                ac2.execute("""
                    UPDATE active_scans SET
                        finished_at=?, bf_attempts=?, bf_found=?,
                        hidden_plugins=?, backup_files=?, injection_tests=?, result_summary=?
                    WHERE id=?
                """, (
                    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
                    0, 0,
                    len(ar.get("hidden_plugins", [])), len(ar.get("backup_files", [])),
                    len(ar.get("injection_findings", [])), summary, active_audit_id,
                ))
                ac2.commit()
            finally:
                ac2.close()
        except Exception as ae2:
            log.warning("No se pudo actualizar registro de auditoría: %s", ae2)

        return jsonify({"status": "ok", "result": ar})
    except Exception as e:
        log.error("Error en análisis activo %s: %s", job_id, e, exc_info=True)
        return jsonify({"error": "Error interno en análisis activo"}), 500


@scan_bp.route("/attack-map/<job_id>")
def attack_map(job_id: str):
    if not _validate_job_id(job_id):
        return jsonify({"error": "job_id inválido"}), 400
    return render_template("attack_map.html", job_id=job_id, api_key=API_KEY)


                                                                               
           
                                                                               

@scan_bp.route("/r/<job_id>")
def permalink(job_id: str):
    if not _validate_job_id(job_id):
        return "ID de escaneo inválido", 400
    result = get_scan_from_db(job_id)
    if not result:
        return render_template("index.html", api_key=API_KEY,
                               permalink_error=f"Resultado '{job_id}' no encontrado.")
    return render_template("index.html", api_key=API_KEY, permalink_job_id=job_id)


                                                                               
          
                                                                               

@scan_bp.route("/api/scan", methods=["POST"])
@require_api_key
@rate_limit(API_RATE_LIMIT)
def api_scan():
    data         = request.get_json(silent=True) or {}
    url          = normalize_url((data.get("url") or "").strip())
    legal        = bool(data.get("legal_accepted", False))
    callback_url = (data.get("callback_url") or "").strip()
    user_ip      = request.remote_addr or "unknown"

    if not url:
        return jsonify({"error": "URL requerida"}), 400

    safe, reason = is_safe_url(url)
    if not safe:
        return jsonify({"error": f"URL no permitida: {reason}"}), 400

    if callback_url:
        cb_safe, cb_reason = is_safe_url(callback_url)
        if not cb_safe:
            return jsonify({"error": f"callback_url no válida: {cb_reason}"}), 400

    with _active_scans_lock:
        slots_left = MAX_CONCURRENT - _active_scans_count
    if slots_left == 0:
        return jsonify({"error": "Servidor al límite de concurrencia. Reintenta en un momento."}), 503

    job_id, _ = _new_job(url, legal=legal, user_ip=user_ip)
    threading.Thread(target=_run_scan, args=(job_id, url, legal, user_ip, callback_url), daemon=True).start()
    log.info("api_scan iniciado: %s → %s (IP: %s)", job_id, url, user_ip)
    return jsonify({
        "job_id": job_id, "status": "running",
        "stream": f"/scan/{job_id}/stream",
        "result": f"/scan/{job_id}/result",
        "_note":  "api_token ignorado desde v5.0 — usa la BD local (vulns.db)",
    }), 202


@scan_bp.route("/api/bulk", methods=["POST"])
@require_api_key
@rate_limit(2)
def api_bulk():
    from urllib.parse import urlparse as _up
    data  = request.get_json(silent=True) or {}
    urls  = data.get("urls") or []
    legal = bool(data.get("legal_accepted", False))

    if not isinstance(urls, list) or not urls:
        return jsonify({"error": "Se requiere 'urls' como lista no vacía"}), 400
    if not legal:
        return jsonify({"error": "legal_accepted debe ser true"}), 400
    if len(urls) > 10:
        return jsonify({"error": "Máximo 10 URLs por llamada bulk"}), 400

    user_ip = request.remote_addr or "unknown"
    jobs    = []

    for raw_url in urls:
        url = (raw_url or "").strip()
        if not url:
            continue
        try:
            p = _up(url)
            if p.scheme not in ("http", "https") or not p.netloc:
                jobs.append({"url": url, "error": "URL inválida"})
                continue
        except Exception:
            jobs.append({"url": url, "error": "URL inválida"})
            continue

        safe, reason = is_safe_url(url)
        if not safe:
            jobs.append({"url": url, "error": f"URL no permitida: {reason}"})
            continue

        job_id, _ = _new_job(url, legal=legal, user_ip=user_ip)
        threading.Thread(target=_run_scan, args=(job_id, url, legal, user_ip, ""), daemon=True).start()
        jobs.append({
            "url": url, "job_id": job_id,
            "stream_url": f"/scan/{job_id}/stream",
            "result_url": f"/scan/{job_id}/result",
        })
        log.info("Bulk scan encolado: %s → %s", job_id, url)

    return jsonify({"jobs": jobs, "count": len(jobs)})


@scan_bp.route("/api/rescan", methods=["POST"])
@require_api_key
@rate_limit(SCAN_RATE_LIMIT)
def rescan():
    data   = request.get_json(silent=True) or {}
    job_id = (data.get("job_id") or "").strip()
    url    = normalize_url((data.get("url") or "").strip())
    legal  = bool(data.get("legal_accepted", False))

    if not legal:
        return jsonify({"error": "Debes confirmar que tienes autorización (legal_accepted: true)"}), 403

    if job_id and not url:
        if not _validate_job_id(job_id):
            return jsonify({"error": "job_id inválido"}), 400
        prev = None
        with _jobs_lock:
            if job_id in _jobs:
                prev = _jobs[job_id]
        if not prev:
            prev = get_scan_from_db(job_id)
        if prev:
            url = prev.get("url") or prev.get("target_url", "")

    if not url:
        return jsonify({"error": "URL o job_id previo requerido"}), 400

    safe, reason = is_safe_url(url)
    if not safe:
        return jsonify({"error": f"URL no permitida: {reason}"}), 400

    callback_url = (data.get("callback_url") or "").strip()
    if callback_url:
        cb_safe, cb_reason = is_safe_url(callback_url)
        if not cb_safe:
            return jsonify({"error": f"callback_url no válida: {cb_reason}"}), 400

    ip         = request.remote_addr or "unknown"
                                                
    try:
        cache_invalidate(url)
    except Exception as _e:
        try:
            log.debug("cache_invalidate suppressed: %s", _e)
        except Exception:
            pass
    new_job_id, _ = _new_job(url, legal=legal, user_ip=ip)
    threading.Thread(target=_run_scan, args=(new_job_id, url, legal, ip, callback_url), daemon=True).start()
    log.info("Rescan iniciado: %s → %s (origen: %s)", new_job_id, url, job_id or "directo")
    return jsonify({
        "job_id": new_job_id, "url": url,
        "stream_url": f"/scan/{new_job_id}/stream",
        "result_url": f"/scan/{new_job_id}/result",
    }), 201


@scan_bp.route("/api/quick-scan", methods=["GET", "POST"])
@require_api_key
@rate_limit(SCAN_RATE_LIMIT)
def quick_scan():
    from urllib.parse import urlparse as _up
    from scanner.core import (
        ScannerConfig, _make_session, detect_wordpress,
        check_security_headers, check_ssl, detect_waf,
    )

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
    else:
        data = request.args

    url   = normalize_url((data.get("url") or "").strip())
    legal = str(data.get("legal_accepted", "false")).lower() in ("true", "1", "yes")

    if not url:
        return jsonify({"error": "url requerida"}), 400
    if not legal:
        return jsonify({"error": "legal_accepted requerido"}), 403

    safe, reason = is_safe_url(url)
    if not safe:
        return jsonify({"error": f"URL no permitida: {reason}"}), 400

    user_ip = _get_client_ip()
    log.info("Quick scan: %s (IP: %s)", url, user_ip)

    cfg     = ScannerConfig(timeout=8, max_workers=8, verify_ssl=VERIFY_SSL)
    session = _make_session(cfg)
    parsed  = _up(url)
    host    = parsed.hostname or ""
    t0      = time.time()
    result  = {"url": url, "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "quick": True}

    if url.startswith("https://") and host:
        try:
            ssl_info = check_ssl(host)
            result["ssl"] = ssl_info.to_dict()
        except Exception as _e:
            result["ssl"] = {"error": str(_e)}

    try:
        resp = session.get(url, timeout=8, allow_redirects=True)
        headers = dict(resp.headers)
        html    = resp.text[:40000]

        is_wp, wp_ver, _, php_ver = detect_wordpress(html, headers)
        result["is_wordpress"] = is_wp
        result["wp_version"]   = wp_ver
        result["php_version"]  = php_ver
        result["server"]       = headers.get("Server", "")

        issues, ok, leaks = check_security_headers(headers)
        result["headers_issues"] = issues
        result["headers_ok"]     = ok
        result["header_leaks"]   = leaks
        result["waf_detected"]   = detect_waf(headers, html)

        try:
            xr = session.head(f"{url.rstrip('/')}/xmlrpc.php", timeout=5, allow_redirects=False)
            result["xmlrpc_enabled"] = xr.status_code in (200, 405)
        except Exception:
            result["xmlrpc_enabled"] = False

        try:
            lg = session.get(f"{url.rstrip('/')}/wp-login.php", timeout=5, allow_redirects=True)
            result["login_exposed"] = lg.status_code == 200 and "wp-login" in lg.text.lower()
        except Exception:
            result["login_exposed"] = False

        exposed_critical = []
        for _p in ["/wp-config.php", "/.env", "/.git/config", "/phpinfo.php", "/wp-content/debug.log"]:
            try:
                _r = session.get(url.rstrip("/") + _p, timeout=4, allow_redirects=False)
                if _r.status_code == 200 and len(_r.text) > 50:
                    exposed_critical.append(_p)
            except Exception:
                pass
        result["exposed_critical"] = exposed_critical

        _rs = 0
        if len(issues) >= 5:              _rs += 10
        if result.get("xmlrpc_enabled"):  _rs += 15
        if exposed_critical:              _rs += 30 * len(exposed_critical[:2])
        if result.get("ssl", {}).get("expired"): _rs += 25
        _rs = min(_rs, 100)
        result["quick_risk"]  = _rs
        result["quick_label"] = "CRÍTICO" if _rs >= 70 else "ALTO" if _rs >= 45 else "MEDIO" if _rs >= 20 else "BAJO"

    except Exception as _e:
        result["error"] = f"No se pudo conectar: {_e}"
    finally:
        try:
            session.close()
        except Exception:
            pass

    result["duration"] = round(time.time() - t0, 2)
    return jsonify(result)


                                                                               
@scan_bp.route("/api/check-wp", methods=["POST"])
@rate_limit(SCAN_RATE_LIMIT)
def check_wp():
    """
    Endpoint ligero que comprueba si una URL es WordPress en ~2-4s.
    Devuelve: { is_wordpress, wp_version, server, status_code, reachable, reason, detail }
    """
    from scanner.core import _make_session, detect_wordpress, ScannerConfig

    def _friendly_unreachable_error(exc: Exception, target_url: str) -> tuple[str, str]:
        raw = str(exc).strip()
        lower = raw.lower()
        host = normalize_url(target_url).split('//')[-1].split('/')[0]

        if any(token in lower for token in (
            'nameresolutionerror',
            'name or service not known',
            'temporary failure in name resolution',
            'failed to resolve',
        )):
            return (
                'No se pudo resolver el dominio',
                f'DNS: revisa si el dominio está bien escrito o si existe ({host})',
            )

        if any(token in lower for token in ('connecttimeout', 'read timed out', 'timeout', 'timed out')):
            return (
                'Tiempo de espera agotado',
                'El sitio no respondió a tiempo. Puede estar caído o demasiado lento.',
            )

        if any(token in lower for token in ('ssl', 'certificate', 'tls')):
            return (
                'Error SSL/TLS',
                'La conexión segura falló o el certificado no pudo validarse.',
            )

        if any(token in lower for token in ('connection refused', 'max retries exceeded')):
            return (
                'No se pudo establecer la conexión',
                'El host rechaza la conexión o no hay servicio escuchando en el puerto 443.',
            )

        short = raw.replace('\n', ' ')
        if len(short) > 120:
            short = short[:117].rstrip() + '...'
        return ('Sitio no alcanzable', short or 'No fue posible conectar con el sitio.')

    data = request.get_json(silent=True) or {}
    raw_url = (data.get("url") or "").strip()
    if not raw_url:
        return jsonify({"error": "URL requerida"}), 400

    url = normalize_url(raw_url)
    safe, reason = is_safe_url(url)
    if not safe:
        return jsonify({"reachable": False, "reason": reason, "is_wordpress": False}), 200

    cfg = ScannerConfig(timeout=6, verify_ssl=VERIFY_SSL)
    session = _make_session(cfg)

    try:
        resp = session.get(url, timeout=6, allow_redirects=True)
        html = resp.text[:30000]
        headers = dict(resp.headers)
        is_wp, wp_ver, _, _ = detect_wordpress(html, headers)

                                                          
        if not is_wp:
            try:
                r2 = session.get(url.rstrip("/") + "/wp-login.php", timeout=4, allow_redirects=True)
                if r2.status_code == 200 and "wp-login" in r2.text.lower():
                    is_wp = True
            except Exception:
                pass

        return jsonify({
            "reachable":    True,
            "is_wordpress": is_wp,
            "wp_version":   wp_ver,
            "status_code":  resp.status_code,
            "server":       headers.get("Server", ""),
            "final_url":    resp.url,
        })
    except Exception as e:
        reason, detail = _friendly_unreachable_error(e, url)
        return jsonify({
            "reachable":    False,
            "is_wordpress": False,
            "reason":       reason,
            "detail":       detail,
        }), 200
    finally:
        try:
            session.close()
        except Exception:
            pass

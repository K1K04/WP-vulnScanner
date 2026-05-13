"""
blueprints/stats.py — Estadísticas de instancia, tendencias y exportación Markdown
====================================================================================
Rutas:
  GET /api/stats              — estadísticas públicas de la instancia
  GET /api/trending           — sitios cuyo riesgo aumenta entre escaneos
  GET /api/top-vulns          — ranking de vulnerabilidades más frecuentes
  GET /api/rate-limit/stats   — stats del rate limiter (requiere api key)
  POST /api/rate-limit/reset  — resetea contador de una IP (requiere api key)
  GET /scan/<id>/markdown     — exporta informe en Markdown
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta

from flask import Blueprint, Response, jsonify, request

from db import get_scan_from_db
from state import (
    APP_VERSION, APP_START, DB_PATH, MAX_CONCURRENT,
    _active_scans_count, _active_scans_lock, _jobs, _jobs_lock,
    _validate_job_id, require_api_key, _int, _db_write_lock,
)

log = logging.getLogger("wpvulnscan.stats")

stats_bp = Blueprint("stats", __name__)


                                                                                

@stats_bp.route("/api/stats")
def api_stats():
    """Estadísticas públicas de la instancia (sin datos sensibles)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        total_scans    = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        total_vulns    = conn.execute("SELECT SUM(vuln_count) FROM scans").fetchone()[0] or 0
        total_critical = conn.execute("SELECT SUM(critical_count) FROM scans").fetchone()[0] or 0
        avg_risk       = conn.execute("SELECT AVG(risk_score) FROM scans").fetchone()[0] or 0
        last_scan_ts   = conn.execute(
            "SELECT MAX(scanned_at) FROM scans"
        ).fetchone()[0] or ""

                                
        risk_dist = {}
        for row in conn.execute("SELECT risk_label, COUNT(*) as n FROM scans GROUP BY risk_label"):
            risk_dist[row["risk_label"]] = row["n"]

                                  
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        scans_24h = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE scanned_at >= ?", (yesterday,)
        ).fetchone()[0]

                          
        api_scans = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE wpscan_api=1"
        ).fetchone()[0]

                            
        try:
            from scanner.vulns_db import get_db_stats, get_db_freshness
            db_stats  = get_db_stats()
            freshness = get_db_freshness()
        except Exception:
            db_stats  = {"total_vulns": 0, "components": 0}
            freshness = {"fresh": False, "days_old": 999}

    finally:
        conn.close()

    with _active_scans_lock:
        active = _active_scans_count
    with _jobs_lock:
        queued = sum(1 for j in _jobs.values() if j.get("status") == "running")

    return jsonify({
        "version":        APP_VERSION,
        "uptime_seconds": round(time.time() - APP_START),
        "scans": {
            "total":       total_scans,
            "last_24h":    scans_24h,
            "active":      active,
            "queued":      queued,
            "capacity":    MAX_CONCURRENT,
            "wpscan_api":  api_scans,
        },
        "findings": {
            "total_vulns":    total_vulns,
            "total_critical": total_critical,
            "avg_risk":       round(avg_risk, 1),
        },
        "risk_distribution": risk_dist,
        "last_scan":         last_scan_ts,
        "vulns_db": {
            "total":     db_stats["total_vulns"],
            "components":db_stats["components"],
            "fresh":     freshness["fresh"],
            "days_old":  freshness["days_old"],
        },
    })


                                                                                

@stats_bp.route("/api/trending")
@require_api_key
def api_trending():
    """
    Sitios cuyo riesgo está empeorando entre escaneos consecutivos.
    Útil para monitorización continua.
    """
    days  = _int(request.args.get("days", 30), 30, 1, 365)
    limit = _int(request.args.get("limit", 10), 10, 1, 50)
    since = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
                                                      
        urls = [
            r["url"] for r in conn.execute("""
                SELECT url, COUNT(*) as n FROM scans
                WHERE scanned_at >= ?
                GROUP BY url HAVING n >= 2
                ORDER BY n DESC LIMIT 100
            """, (since,)).fetchall()
        ]

        trending = []
        for url in urls:
            rows = conn.execute("""
                SELECT id, scanned_at, risk_score, risk_label, vuln_count, critical_count
                FROM scans WHERE url = ? ORDER BY scanned_at ASC
            """, (url,)).fetchall()
            if len(rows) < 2:
                continue
            first = dict(rows[0])
            last  = dict(rows[-1])
            delta = last["risk_score"] - first["risk_score"]

            if delta > 0:                            
                trending.append({
                    "url":          url,
                    "scans":        len(rows),
                    "risk_first":   first["risk_score"],
                    "risk_last":    last["risk_score"],
                    "risk_delta":   delta,
                    "risk_label":   last["risk_label"],
                    "last_scan_id": last["id"],
                    "last_scan_at": last["scanned_at"],
                    "trend":        "worsening" if delta > 10 else "slightly_worse",
                    "vulns_last":   last["vuln_count"],
                    "critical_last":last["critical_count"],
                })

        trending.sort(key=lambda x: x["risk_delta"], reverse=True)
        return jsonify({
            "trending":  trending[:limit],
            "total":     len(trending),
            "period_days": days,
        })
    finally:
        conn.close()


                                                                                

@stats_bp.route("/api/top-vulns")
@require_api_key
def api_top_vulns():
    """Ranking de vulnerabilidades más encontradas en todos los escaneos."""
    limit = _int(request.args.get("limit", 20), 20, 1, 100)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("""
            SELECT result_json FROM scans
            WHERE result_json IS NOT NULL AND vuln_count > 0
            ORDER BY scanned_at DESC LIMIT 200
        """).fetchall()
    finally:
        conn.close()

    counter: dict[str, dict] = {}
    for row in rows:
        try:
            data = json.loads(row[0])
            for v in data.get("vulnerabilities", []):
                if not isinstance(v, dict):
                    continue
                key = v.get("cve_id") or v.get("cve") or v.get("title", "unknown")
                if not key:
                    continue
                if key not in counter:
                    counter[key] = {
                        "id":        key,
                        "title":     v.get("title", key),
                        "severity":  v.get("severity", "medium"),
                        "cvss":      v.get("cvss_score"),
                        "component": v.get("plugin_slug") or v.get("component", ""),
                        "fixed_in":  v.get("fixed_in", ""),
                        "count":     0,
                        "sites":     set(),
                    }
                counter[key]["count"] += 1
                counter[key]["sites"].add(data.get("target_url", ""))
        except Exception:
            pass

    top = sorted(counter.values(), key=lambda x: x["count"], reverse=True)[:limit]
    for item in top:
        item["sites"] = len(item["sites"])                        

    return jsonify({"top_vulns": top, "total_unique": len(counter)})


                                                                                

@stats_bp.route("/api/rate-limit/stats")
@require_api_key
def rate_limit_stats():
    """Stats del rate limiter — IPs más activas y contadores actuales."""
    window = _int(request.args.get("window", 60), 60, 10, 3600)
    now    = time.time()
    cutoff = now - window

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("""
            SELECT ip, endpoint, COUNT(*) as hits
            FROM rate_limit WHERE ts >= ?
            GROUP BY ip, endpoint ORDER BY hits DESC LIMIT 30
        """, (cutoff,)).fetchall()
        total = conn.execute(
            "SELECT COUNT(DISTINCT ip) FROM rate_limit WHERE ts >= ?", (cutoff,)
        ).fetchone()[0]
        blocked = conn.execute(
            "SELECT COUNT(*) FROM rate_limit WHERE ts >= ?", (cutoff,)
        ).fetchone()[0]
    finally:
        conn.close()

    return jsonify({
        "window_seconds": window,
        "unique_ips":     total,
        "total_requests": blocked,
        "top_ips":        [dict(r) for r in rows],
    })


@stats_bp.route("/api/rate-limit/reset", methods=["POST"])
@require_api_key
def rate_limit_reset():
    """Resetea el contador de rate limit de una IP específica."""
    data = request.get_json(silent=True) or {}
    ip   = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip requerida"}), 400

    with _db_write_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM rate_limit WHERE ip=?", (ip,))
        conn.commit()
        conn.close()

    log.info("Rate limit reseteado para IP: %s", ip)
    return jsonify({"status": "ok", "ip": ip})


                                                                                 

@stats_bp.route("/scan/<job_id>/markdown")
@require_api_key
def download_markdown(job_id: str):
    """Exporta el informe en Markdown — ideal para wikis, Notion, Confluence."""
    if not _validate_job_id(job_id):
        return jsonify({"error": "job_id inválido"}), 400

    result = None
    with _jobs_lock:
        entry = _jobs.get(job_id)
        if entry and entry.get("result"):
            result = entry["result"]
    if result is None:
        result = get_scan_from_db(job_id)
    if not result:
        return jsonify({"error": "Escaneo no encontrado"}), 404

    md = _build_markdown(result, job_id)
    domain = (result.get("target_url") or "").split("//")[-1].split("/")[0]
    fname  = f"wpvuln-{domain}-{job_id[:6]}.md"

    return Response(
        md.encode("utf-8"),
        mimetype="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


def _sev_emoji(sev: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}.get(sev, "⚪")


def _risk_emoji(score: int) -> str:
    if score >= 70: return "🔴"
    if score >= 45: return "🟠"
    if score >= 20: return "🟡"
    return "🟢"


def _build_markdown(r: dict, job_id: str) -> str:
    """Genera un informe Markdown completo y bien formateado."""
    url     = r.get("target_url", "")
    score   = r.get("risk_score", 0)
    label   = r.get("risk_label", "BAJO")
    scanned = r.get("scanned_at", "")
    s       = r.get("summary", {})
    vulns   = r.get("vulnerabilities", [])
    plugins = r.get("plugins", [])
    themes  = r.get("themes", [])
    exposed = r.get("exposed_files", [])
    users   = r.get("users", [])
    h_bad   = r.get("headers_issues", [])
    h_ok    = r.get("headers_ok", [])
    ssl     = r.get("ssl_info") or {}
    malware = r.get("malware_indicators", [])

    lines = [
        "# 🔍 WP VulnScanner — Informe de Seguridad",
        "",
        f"> Generado por **WP VulnScanner v{APP_VERSION}**",
        "",
        "---",
        "",
        "## 📋 Resumen ejecutivo",
        "",
        "| Campo | Valor |",
        "|-------|-------|",
        f"| 🎯 Sitio objetivo | `{url}` |",
        f"| {_risk_emoji(score)} Puntuación de riesgo | **{score}/100 — {label}** |",
        f"| 📅 Fecha del escaneo | {scanned} |",
        f"| 🆔 Scan ID | `{job_id}` |",
        f"| ⚙️ Motor | {'WPScan API (tiempo real)' if r.get('wpscan_api_used') else 'Base de datos offline'} |",
        "",
    ]

                  
    lines += [
        "### Métricas clave",
        "",
        "| Vulnerabilidades | Críticas | Altas | Plugins | Archivos expuestos | Usuarios |",
        "|:---:|:---:|:---:|:---:|:---:|:---:|",
        f"| **{s.get('vulns_found', 0)}** | 🔴 {s.get('critical_vulns', 0)} | 🟠 {s.get('high_vulns', 0)} | {s.get('plugins_found', 0)} | {s.get('exposed_files', 0)} | {s.get('users_found', 0)} |",
        "",
    ]

                    
    lines += [
        "---",
        "",
        "## 🌐 Información del sitio",
        "",
        "| Parámetro | Valor |",
        "|-----------|-------|",
        f"| WordPress | {'✅ Detectado' if r.get('is_wordpress') else '❓ No confirmado'} |",
    ]
    if r.get("wp_version"):
        outdated = " ⚠️ **DESACTUALIZADO**" if r.get("wp_outdated") else " ✅"
        lines.append(f"| Versión WP | `{r['wp_version']}`{outdated} |")
        if r.get("wp_outdated") and r.get("wp_latest_version"):
            lines.append(f"| Última versión WP | `{r['wp_latest_version']}` |")
    lines += [
        f"| Servidor | {r.get('server_info') or '`oculto ✅`'} |",
        f"| PHP | {r.get('php_version') or '`oculta ✅`'} |",
        f"| XML-RPC | {'⚠️ **Activo**' if r.get('xmlrpc_enabled') else '✅ Desactivado'} |",
        f"| Login WP | {'⚠️ **Accesible**' if r.get('login_exposed') else '✅ Protegido'} |",
    ]
    if r.get("waf_detected"):
        lines.append(f"| WAF detectado | {', '.join(r['waf_detected'])} |")
    lines.append("")

         
    if ssl and ssl.get("valid"):
        dl = ssl.get("days_left", 0)
        ssl_status = "❌ EXPIRADO" if ssl.get("expired") else (
            f"⚠️ {dl} días restantes" if dl < 30 else f"✅ {dl} días restantes"
        )
        lines += [
            f"| SSL/HTTPS | {ssl_status} |",
            f"| Emisor SSL | {ssl.get('issuer', '?')} |",
        ]
    lines.append("")

                      
    lines += [
        "---",
        "",
        f"## 🐛 Vulnerabilidades ({len(vulns)})",
        "",
    ]
    if not vulns:
        lines.append("✅ No se encontraron vulnerabilidades conocidas.")
    else:
        by_sev: dict[str, list] = {}
        for v in vulns:
            if not isinstance(v, dict):
                continue
            sev = v.get("severity", "medium")
            by_sev.setdefault(sev, []).append(v)

        for sev in ["critical", "high", "medium", "low", "info"]:
            group = by_sev.get(sev, [])
            if not group:
                continue
            lines += [
                f"### {_sev_emoji(sev)} {sev.upper()} ({len(group)})",
                "",
                "| CVE/ID | Título | Componente | Versión | Fix |",
                "|--------|--------|------------|---------|-----|",
            ]
            for v in group:
                cve  = v.get("cve_id") or v.get("cve") or "—"
                slug = v.get("plugin_slug") or v.get("component", "—")
                ver  = v.get("plugin_version") or v.get("version") or "?"
                fix  = f"`{v['fixed_in']}`" if v.get("fixed_in") else "Sin fix"
                title = (v.get("title") or "").replace("|", "\\|")[:60]
                cve_link = f"[{cve}](https://nvd.nist.gov/vuln/detail/{cve})" if cve.startswith("CVE-") else cve
                lines.append(f"| {cve_link} | {title} | `{slug}` | `{ver}` | {fix} |")
            lines.append("")

                     
    outdated_plugins = [p for p in plugins if isinstance(p, dict) and p.get("is_outdated")]
    if plugins or themes:
        lines += [
            "---",
            "",
            f"## 🔌 Componentes detectados ({len(plugins)} plugins, {len(themes)} temas)",
            "",
        ]
        if outdated_plugins:
            lines += [
                f"⚠️ **{len(outdated_plugins)} componentes desactualizados**",
                "",
                "| Tipo | Slug | Versión instalada | Última versión |",
                "|------|------|-------------------|----------------|",
            ]
            for p in outdated_plugins:
                lines.append(
                    f"| {'Plugin' if p.get('type') != 'theme' else 'Tema'} "
                    f"| `{p.get('slug','')}` "
                    f"| `{p.get('version') or '?'}` "
                    f"| `{p.get('latest_version') or '?'}` |"
                )
            lines.append("")

                        
    lines += ["---", "", f"## 📂 Archivos expuestos ({len(exposed)})", ""]
    if not exposed:
        lines.append("✅ No se encontraron archivos sensibles expuestos.")
    else:
        lines += [
            "| Severidad | Ruta | Descripción |",
            "|-----------|------|-------------|",
        ]
        for f in exposed:
            if not isinstance(f, dict):
                continue
            lines.append(
                f"| {_sev_emoji(f.get('severity','high'))} {f.get('severity','high').upper()} "
                f"| `{f.get('path','')}` "
                f"| {f.get('description','')} |"
            )
    lines.append("")

                    
    lines += ["---", "", "## 🛡️ Cabeceras HTTP de seguridad", ""]
    if h_bad:
        lines += [
            f"**{len(h_bad)} cabeceras ausentes:**",
            "",
        ]
        for h in h_bad:
            lines.append(f"- ❌ `{h}`")
        lines.append("")
    if h_ok:
        lines.append("<details><summary>✅ Cabeceras presentes</summary>")
        lines.append("")
        for h in h_ok:
            lines.append(f"- ✅ `{h}`")
        lines.append("</details>")
        lines.append("")

              
    if users:
        lines += [
            "---",
            "",
            f"## 👤 Usuarios enumerados ({len(users)})",
            "",
            "> ⚠️ Usuarios enumerados sin autenticación — facilitan ataques de fuerza bruta",
            "",
            "| ID | Login | Nombre | Fuente |",
            "|----|-------|--------|--------|",
        ]
        for u in users:
            if not isinstance(u, dict):
                continue
            lines.append(
                f"| {u.get('id','?')} | `{u.get('login') or '?'}` "
                f"| {u.get('display_name') or '?'} | {u.get('source','?')} |"
            )
        lines.append("")

             
    if malware:
        lines += [
            "---",
            "",
            f"## ☣️ Indicadores de Malware ({len(malware)})",
            "",
        ]
        for m in malware:
            lines.append(f"- ☣️ {m}")
        lines.append("")

                
    rep = r.get("reputation") or {}
    if rep and (rep.get("blacklisted") or rep.get("spam_score", 0) > 0):
        lines += [
            "---",
            "",
            "## ⚠️ Reputación",
            "",
            f"- Blacklisted: {'⚠️ Sí' if rep.get('blacklisted') else '✅ No'}",
            f"- Spam score: {rep.get('spam_score', 0)}",
            "",
        ]

                                
    lines += [
        "---",
        "",
        "## 🔧 Plan de remediación recomendado",
        "",
    ]
    priority = 1
    if r.get("wp_outdated"):
        lines.append(f"{priority}. **[CRÍTICO]** Actualizar WordPress a la última versión estable.")
        priority += 1
    for v in vulns:
        if isinstance(v, dict) and v.get("severity") in ("critical", "high"):
            fix = f"Actualizar a v{v['fixed_in']}" if v.get("fixed_in") else "Desactivar o reemplazar el componente"
            lines.append(f"{priority}. **[{v['severity'].upper()}]** {v.get('title','')} — {fix}")
            priority += 1
            if priority > 8:
                lines.append(f"{priority}. *(y {len(vulns) - 8} más...)*")
                break
    if r.get("xmlrpc_enabled"):
        lines.append(f"{priority}. **[MEDIO]** Desactivar XML-RPC si no se usa (`xmlrpc_enabled`).")
        priority += 1
    if h_bad:
        lines.append(f"{priority}. **[MEDIO]** Añadir las {len(h_bad)} cabeceras HTTP de seguridad faltantes.")
        priority += 1
    if exposed:
        lines.append(f"{priority}. **[ALTO]** Restringir acceso a {len(exposed)} archivos sensibles expuestos.")
    lines.append("")

            
    lines += [
        "---",
        "",
        f"*Informe generado por [WP VulnScanner](https://github.com/wpvulnscan) v{APP_VERSION} · "
        f"Scan ID: `{job_id}` · {scanned}*",
        "",
        "> ⚖️ Auditoría externa y pasiva. El solicitante declara tener autorización "
        "expresa del propietario del sitio para realizar esta auditoría.",
    ]

    return "\n".join(lines)

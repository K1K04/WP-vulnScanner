"""
generate_standalone_html — FIX #18
Genera un HTML standalone completo con todos los datos del escaneo.
Sin dependencias externas, CSS inline, SVG gauge.
"""

from __future__ import annotations
import html as _html
import math
from datetime import datetime

def _e(v) -> str:
    """Bug 6 fix: escape HTML special chars in externally-sourced data."""
    return _html.escape(str(v)) if v is not None else ""


def generate_standalone_html(result: dict) -> bytes:
    r = result
    s = r.get("summary", {})
    risk_score = r.get("risk_score", 0)
    risk_color = r.get("risk_color", "#8b949e")
    risk_label = r.get("risk_label", "N/D")

               
    angle = (risk_score / 100) * 180
    x_end = 100 + 70 * math.cos((angle - 180) * math.pi / 180)
    y_end = 100 + 70 * math.sin((angle - 180) * math.pi / 180)

    sev_map = {
        "critical": "#ff4757", "high": "#ff6b35",
        "medium":   "#ffa502", "low":  "#2ed573", "info": "#00d4ff",
    }
    sev_labels = {
        "critical": "CRÍTICO", "high": "ALTO",
        "medium": "MEDIO", "low": "BAJO", "info": "INFO",
    }

    def sev_badge(sev):
        c = sev_map.get(sev, "#8b949e")
        lbl = sev_labels.get(sev, sev.upper())
        return (f'<span style="background:{c};color:#000;font-size:10px;'
                f'padding:2px 7px;border-radius:3px;font-weight:700">{lbl}</span>')

    def check_row(label, ok, ok_text="✓ OK", fail_text="⚠ Problema"):
        val = (f'<span style="color:#2ed573">{ok_text}</span>' if ok
               else f'<span style="color:#ffa502">{fail_text}</span>')
        return f"<tr><td>{label}</td><td>{val}</td></tr>"

    def info_row(label, value):
        return f"<tr><td style='color:#8b949e'>{label}</td><td>{value}</td></tr>"

                                                                                 
    plan = []
    crit = s.get("critical_vulns", 0)
    high = s.get("high_vulns", 0)
    if crit:
        plan.append(("🔴 INMEDIATO", f"{crit} vulns críticas — desactivar plugins afectados"))
    if r.get("debug_mode", {}).get("debug_active"):
        plan.append(("🔴 INMEDIATO", "WP_DEBUG=true activo en producción"))
    if r.get("redirect_chain", {}).get("suspicious"):
        plan.append(("🔴 INMEDIATO", "Redirección sospechosa — posible malware SEO"))
    if r.get("rest_api_issues", {}).get("allows_edit_context"):
        plan.append(("🔴 INMEDIATO", "REST API expone RAW sin auth (context=edit)"))
    if high:
        plan.append(("🟠 ESTA SEMANA", f"{high} vulns altas — actualizar urgente"))
    if r.get("cors_issues", {}).get("vulnerable"):
        plan.append(("🟠 ESTA SEMANA", "CORS misconfiguration en /wp-json/"))
    if r.get("tls_analysis", {}).get("deprecated_protocol"):
        plan.append(("🟠 ESTA SEMANA", "Deshabilitar TLS 1.0/1.1"))
    if r.get("rest_api_issues", {}).get("exposes_emails"):
        plan.append(("🟠 ESTA SEMANA", "REST API expone emails de usuarios"))
    outdated = (s.get("outdated_plugins", 0) + s.get("outdated_themes", 0))
    if outdated:
        plan.append(("🟡 ESTE MES", f"Actualizar {outdated} componentes desactualizados"))
    if r.get("xmlrpc_enabled"):
        plan.append(("🟡 ESTE MES", "Deshabilitar XML-RPC"))
    if r.get("wp_cron_abuse", {}).get("abusable"):
        plan.append(("🟡 ESTE MES", "Bloquear /wp-cron.php desde internet"))
    if not plan:
        plan.append(("✅ BUEN ESTADO", "No se detectaron problemas críticos"))

    plan_rows = "".join(
        f'<div class="plan-row"><div class="plan-pri">{p}</div>'
        f'<div style="font-size:12px">{t}</div></div>'
        for p, t in plan
    )

                                                                                
    vulns = r.get("vulnerabilities", [])
    vuln_rows = ""
    for v in vulns:
        sev = v.get("severity", "info")
        c   = sev_map.get(sev, "#8b949e")
        cve = v.get("cve_id", "")
        cve_html = (f'<a href="https://nvd.nist.gov/vuln/detail/{_e(cve)}" '
                    f'style="color:#00d4ff" target="_blank">{_e(cve)}</a>') if cve else ""
        fix = v.get("fixed_in", "")
        vuln_rows += (
            f'<tr>'
            f'<td>{sev_badge(sev)}</td>'
            f'<td style="font-size:12px">{_e(v.get("title",""))}</td>'
            f'<td style="font-size:11px;color:#8b949e">'
            f'{_e(v.get("plugin_slug",""))} v{_e(v.get("plugin_version","?"))}</td>'
            f'<td style="font-size:11px">{cve_html}</td>'
            f'<td style="font-size:11px;color:{sev_map.get(sev,"#8b949e")}">'
            f'{v.get("cvss_score","")}</td>'
            f'<td style="font-size:11px;color:#2ed573">'
            f'{"→ v"+_e(fix) if fix else ""}</td>'
            f'</tr>'
        )
    if not vuln_rows:
        vuln_rows = '<tr><td colspan="6" style="color:#2ed573;text-align:center">✓ Sin vulnerabilidades</td></tr>'

                                                                                
    plugin_rows = ""
    for p in r.get("plugins", []):
        outdated_txt = ('<span style="color:#ff4757">⚠ DESACT.</span>'
                        if p.get("is_outdated") else
                        '<span style="color:#2ed573">✓</span>')
        plugin_rows += (
            f'<tr>'
            f'<td>{_e(p.get("slug",""))}</td>'
            f'<td>{_e(p.get("version","?"))}</td>'
            f'<td>{_e(p.get("latest_version",""))}</td>'
            f'<td>{outdated_txt}</td>'
            f'<td style="font-size:11px;color:#8b949e">{_e(p.get("detected_via",""))}</td>'
            f'</tr>'
        )

                                                                                
    files_html = ""
    for f in r.get("exposed_files", []):
        if isinstance(f, str):
            f = {"path": f, "description": "", "severity": "high"}
        c = sev_map.get(f.get("severity", "high"), "#ff6b35")
        files_html += (
            f'<div style="background:#161b22;border-left:3px solid {c};'
            f'padding:8px 12px;margin:4px 0;font-size:12px">'
            f'<code style="color:#00d4ff">{f.get("path","")}</code>'
            f' — {f.get("description","")}</div>'
        )
    if not files_html:
        files_html = '<p style="color:#2ed573">✓ Sin archivos expuestos</p>'

                                                                                
    cors   = r.get("cors_issues", {})
    debug  = r.get("debug_mode", {})
    tls    = r.get("tls_analysis", {})
    rest   = r.get("rest_api_issues", {})
    redir  = r.get("redirect_chain", {})
    timing = r.get("timing_plugins", [])
    post_i = r.get("post_injections", [])
    csp    = r.get("csp_analysis", {})
    hsts   = r.get("hsts_analysis", {})
    jst    = r.get("js_threats", [])
    stack  = r.get("server_stack", {})

    def findings_html(findings, key="issue", sev_key="severity"):
        if not findings:
            return '<p style="color:#2ed573">✓ Sin hallazgos</p>'
        out = ""
        for f in findings:
            issue = f.get(key, str(f))
            sev   = f.get(sev_key, "medium")
            c     = sev_map.get(sev, "#8b949e")
            out  += (f'<div style="background:#161b22;border-left:3px solid {c};'
                     f'padding:8px 12px;margin:4px 0;font-size:12px">'
                     f'<span style="color:{c};font-weight:700">[{sev.upper()}]</span>'
                     f' {issue}</div>')
        return out

    timing_html = ""
    if timing:
        for p in timing:
            timing_html += (
                f'<div style="background:#161b22;padding:8px 12px;margin:4px 0;font-size:12px">'
                f'<span style="color:#00d4ff">{p.get("slug","")}</span>'
                f' — avg: {p.get("avg_response_ms","?")}ms'
                f' · baseline: {p.get("baseline_ms","?")}ms'
                f' · confianza: {p.get("confidence","?")}%</div>'
            )
    else:
        timing_html = '<p style="color:#8b949e;font-size:12px">Sin plugins adicionales detectados por timing</p>'

    stack_rows = ""
    for k, v in stack.items():
        if v:
            stack_rows += f"<tr><td style='color:#8b949e'>{_e(k)}</td><td>{_e(v)}</td></tr>"

    jst_html = "".join(
        f'<div style="color:#ff4757;font-size:12px;margin:3px 0">⚠ {t}</div>'
        for t in jst
    ) or '<p style="color:#2ed573">✓ Sin amenazas JS</p>'

    users_rows = ""
    for u in r.get("users", []):
        users_rows += (
            f'<tr><td>{u.get("id","")}</td>'
            f'<td style="color:#ffa502">{u.get("login","")}</td>'
            f'<td>{u.get("display_name","")}</td>'
            f'<td style="font-size:11px;color:#8b949e">{u.get("source","")}</td></tr>'
        )

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    waf_str = ", ".join(r.get("waf_detected", []))

    multisite = r.get("multisite_info", {})
    custom_login = r.get("custom_login", {})
    cron = r.get("wp_cron_abuse", {})

    ssl = r.get("ssl_info") or {}
    ssl_text = ("✓ " + str(ssl.get("days_left", "?")) + " días"
                if ssl.get("valid") else "⚠ Inválido o no analizado")
    ssl_color = "#2ed573" if ssl.get("valid") else "#ff4757"

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WP VulnScanner v5.4 — {r.get("target_url","")}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:"Courier New",monospace;background:#0d1117;color:#c9d1d9;
      padding:40px 30px;max-width:1100px;margin:0 auto;font-size:13px;line-height:1.6}}
h1{{color:#39ff14;font-size:22px;margin-bottom:6px}}
h2{{color:#00d4ff;border-bottom:1px solid #21262d;padding-bottom:8px;
    font-size:14px;margin:24px 0 12px;text-transform:uppercase;letter-spacing:1px}}
table{{width:100%;border-collapse:collapse;margin-bottom:14px;font-size:12px}}
td,th{{border:1px solid #21262d;padding:7px 10px;text-align:left;vertical-align:top}}
th{{background:#161b22;color:#00d4ff;font-weight:700}}
tr:nth-child(even){{background:#0a0e14}}
.meta{{color:#8b949e;font-size:11px;margin-bottom:24px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:24px}}
.kpi{{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:14px}}
.kpi-num{{font-size:28px;font-weight:900;line-height:1}}
.kpi-lbl{{font-size:11px;color:#8b949e;margin-top:4px}}
.plan-row{{display:flex;gap:16px;align-items:flex-start;
           background:#161b22;border:1px solid #21262d;border-radius:6px;
           padding:10px 14px;margin:5px 0}}
.plan-pri{{min-width:160px;font-weight:700;font-size:11px}}
a{{color:#00d4ff;text-decoration:none}}
footer{{color:#484f58;font-size:11px;text-align:center;margin-top:32px;
        border-top:1px solid #21262d;padding-top:14px}}
</style>
</head>
<body>

<h1>🔍 WP VulnScanner v5.4 — Informe de Seguridad</h1>
<div class="meta">
  <strong style="color:#c9d1d9">{r.get("target_url","")}</strong> &nbsp;·&nbsp;
  Escaneado: {r.get("scanned_at","")} &nbsp;·&nbsp;
  Duración: {r.get("duration",0)}s &nbsp;·&nbsp;
  Generado: {now_str}
  {(" &nbsp;·&nbsp; WAF: <span style='color:#2ed573'>" + waf_str + "</span>") if waf_str else ""}
</div>

<!-- Risk gauge SVG -->
<div style="display:flex;align-items:center;gap:28px;background:#161b22;
            border:1px solid #21262d;border-radius:10px;padding:20px;margin-bottom:24px">
  <svg width="200" height="120" viewBox="0 0 200 120">
    <path d="M 30 100 A 70 70 0 0 1 170 100"
          stroke="#21262d" stroke-width="14" fill="none"/>
    <path d="M 30 100 A 70 70 0 0 1 {x_end:.1f} {y_end:.1f}"
          stroke="{risk_color}" stroke-width="14" fill="none" stroke-linecap="round"/>
    <text x="100" y="90" text-anchor="middle" font-family="Courier New"
          font-size="32" font-weight="900" fill="{risk_color}">{risk_score}</text>
    <text x="100" y="108" text-anchor="middle" font-family="Courier New"
          font-size="11" fill="#8b949e">{risk_label} / 100</text>
  </svg>
  <div style="flex:1">
    <div style="font-size:32px;font-weight:900;color:{risk_color}">{risk_label}</div>
    <div style="color:#8b949e;font-size:12px;margin:4px 0">Puntuación de riesgo global</div>
    <div style="height:8px;background:#21262d;border-radius:4px;overflow:hidden;margin-top:8px">
      <div style="width:{risk_score}%;height:100%;background:{risk_color};border-radius:4px"></div>
    </div>
  </div>
</div>

<!-- KPIs -->
<div class="grid">
  <div class="kpi"><div class="kpi-num" style="color:#ff4757">{s.get("vulns_found",0)}</div>
    <div class="kpi-lbl">Vulnerabilidades</div>
    <div style="font-size:10px;color:#8b949e;margin-top:3px">
      {s.get("critical_vulns",0)} crít. · {s.get("high_vulns",0)} alt. · {s.get("medium_vulns",0)} med.</div></div>
  <div class="kpi"><div class="kpi-num" style="color:#00d4ff">{s.get("plugins_found",0)}</div>
    <div class="kpi-lbl">Plugins</div>
    <div style="font-size:10px;color:#ffa502;margin-top:3px">{s.get("outdated_plugins",0)} desactualizados</div></div>
  <div class="kpi"><div class="kpi-num" style="color:#ff6b35">{s.get("exposed_files",0)}</div>
    <div class="kpi-lbl">Archivos expuestos</div></div>
  <div class="kpi"><div class="kpi-num" style="color:#ff6b35">{s.get("users_found",0)}</div>
    <div class="kpi-lbl">Usuarios enumerables</div></div>
  <div class="kpi"><div class="kpi-num" style="color:#ffa502">{s.get("header_issues",0)}</div>
    <div class="kpi-lbl">Headers faltantes</div></div>
  <div class="kpi"><div class="kpi-num" style="color:#ff4757">{s.get("malware_found",0)}</div>
    <div class="kpi-lbl">Malware/Spam</div></div>
</div>

<h2>📋 Plan de Acción Priorizado</h2>
{plan_rows}

<h2>ℹ️ Información del Sitio</h2>
<table>
  {info_row("URL objetivo", r.get("target_url",""))}
  {info_row("WordPress", (r.get("wp_version","?") +
    (' <span style="color:#ff4757">⚠ DESACTUALIZADO → ' + r.get("wp_latest_version","") + '</span>'
     if r.get("wp_outdated") else ' <span style="color:#2ed573">✓</span>'))
    if r.get("wp_version") else '<span style="color:#2ed573">No detectada ✓</span>')}
  {info_row("Servidor", r.get("server_info","") or '<span style="color:#2ed573">Oculto ✓</span>')}
  {info_row("PHP", r.get("php_version","") or '<span style="color:#2ed573">Oculta ✓</span>')}
  {info_row("XML-RPC", '<span style="color:#ff4757">⚠ ACTIVO</span>' if r.get("xmlrpc_enabled") else '<span style="color:#2ed573">✓ Desactivado</span>')}
  {info_row("SSL/TLS", f'<span style="color:{ssl_color}">{ssl_text}</span>')}
  {info_row("WAF/CDN", f'<span style="color:#2ed573">🛡 {waf_str}</span>' if waf_str else '<span style="color:#ffa502">Sin WAF detectado</span>')}
  {info_row("CORS REST API", '<span style="color:#ff4757">⚠ ' + cors.get("severity","").upper() + '</span>' if cors.get("vulnerable") else '<span style="color:#2ed573">✓ OK</span>')}
  {info_row("WP_DEBUG", '<span style="color:#ff4757">⚠ ACTIVO en producción</span>' if debug.get("debug_active") else '<span style="color:#2ed573">✓ Desactivado</span>')}
  {info_row("TLS deprecado", '<span style="color:#ff4757">⚠ ' + ", ".join(tls.get("weak_protocol_list",[])) + '</span>' if tls.get("deprecated_protocol") else '<span style="color:#2ed573">✓ No detectado</span>')}
  {info_row("wp-cron externo", '<span style="color:#ff6b35">⚠ Abusable (' + str(cron.get("response_time_ms","?")) + 'ms)</span>' if cron.get("abusable") else '<span style="color:#2ed573">✓ No abusable</span>')}
  {info_row("Login URL", '<span style="color:#ffa502">🔒 ' + custom_login.get("custom_url","") + '</span>' if custom_login.get("custom_url") else ('<span style="color:#ffa502">⚠ /wp-login.php expuesto</span>' if custom_login.get("original_accessible") else '<span style="color:#8b949e">N/D</span>'))}
  {info_row("Multisite", '<span style="color:#ffa502">⚠ Detectado</span>' if multisite.get("is_multisite") else '<span style="color:#2ed573">✓ Instalación simple</span>')}
  {info_row("Redirect UA", '<span style="color:#ff4757">🚨 Redirección sospechosa</span>' if redir.get("suspicious") else '<span style="color:#2ed573">✓ Normal</span>')}
</table>

<h2>⚠️ Vulnerabilidades ({len(vulns)})</h2>
<table>
  <tr><th>Severidad</th><th>Título</th><th>Componente</th><th>CVE</th><th>CVSS</th><th>Solución</th></tr>
  {vuln_rows}
</table>

<h2>🔌 Plugins ({len(r.get("plugins",[]))})</h2>
<table>
  <tr><th>Slug</th><th>Versión</th><th>Última</th><th>Estado</th><th>Detección</th></tr>
  {plugin_rows or "<tr><td colspan='5' style='color:#8b949e'>Sin plugins detectados</td></tr>"}
</table>

<h2>📁 Archivos Expuestos ({s.get("exposed_files",0)})</h2>
{files_html}

<h2>🔒 Cabeceras de Seguridad</h2>
<table>
  {"".join(f"<tr><td style='color:#ffa502'>⚠ {h}</td></tr>" for h in r.get("headers_issues",[]))}
  {"".join(f"<tr><td style='color:#2ed573'>✓ {h}</td></tr>" for h in r.get("headers_ok",[]))}
  {"<tr><td style='color:#8b949e'>No analizado</td></tr>" if not r.get("headers_issues") and not r.get("headers_ok") else ""}
</table>

<h2>🌐 CORS / REST API</h2>
{findings_html(cors.get("findings",[]))}
{findings_html(rest.get("findings",[]))}

<h2>🐛 WP_DEBUG en Producción</h2>
{"<div style='background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.3);border-radius:6px;padding:12px;font-size:12px;color:#ff4757'>⚠ WP_DEBUG activo — expone rutas internas y stack traces PHP en HTML público</div>" if debug.get("debug_active") else "<p style='color:#2ed573'>✓ No detectado</p>"}

<h2>🔐 TLS / Cipher Suite</h2>
{findings_html(tls.get("findings",[]))}
<table>
  {info_row("Protocolo TLS", tls.get("tls_version","") or "N/D")}
  {info_row("Cipher suite", tls.get("cipher_suite","") or "N/D")}
  {info_row("HSTS Preload", '<span style="color:#2ed573">✓ En lista</span>' if tls.get("hsts_preload") else "No incluido")}
</table>

<h2>⏰ wp-cron Externo</h2>
{"<div style='color:#ff6b35;font-size:12px'>⚠ wp-cron.php es accesible externamente y puede ser abusado para generar carga masiva en el servidor.</div>" if cron.get("abusable") else "<p style='color:#2ed573'>✓ No abusable externamente</p>"}
{"<div style='font-size:11px;color:#8b949e;margin-top:6px'>Tiempo de respuesta: " + str(cron.get("response_time_ms","?")) + "ms</div>" if cron.get("accessible") else ""}

<h2>🔗 Cadenas de Redirección (Googlebot)</h2>
{"<div style='color:#ff4757;font-size:13px;font-weight:700'>🚨 Redirección sospechosa detectada — posible malware SEO o cloaking</div>" if redir.get("suspicious") else "<p style='color:#2ed573'>✓ Sin redirecciones sospechosas detectadas</p>"}
{"".join(f'<div style="background:#161b22;padding:8px 12px;margin:4px 0;font-size:12px"><strong style=color:#ffa502>{d.get("agent","")}</strong>: {d.get("issue","")}</div>' for d in redir.get("discrepancies",[]))}

<h2>🎯 Plugins Detectados por Timing ({len(timing)})</h2>
{timing_html}

<h2>💉 Tests de Inyección POST ({len(post_i)})</h2>
{findings_html(post_i, "description", "severity")}

<h2>🌐 CSP / HSTS</h2>
<table>
  {check_row("CSP presente", csp.get("present"), "✓ Presente", "⚠ Ausente")}
  {check_row("unsafe-inline", not csp.get("unsafe_inline"), "✓ No", "⚠ Detectado")}
  {check_row("unsafe-eval", not csp.get("unsafe_eval"), "✓ No", "⚠ Detectado")}
  {info_row("HSTS", f'<span style="color:#2ed573">✓ max-age={hsts.get("max_age","?")} {"includeSubDomains" if hsts.get("include_subdomains") else ""}</span>' if hsts.get("present") else '<span style="color:#ffa502">⚠ Ausente</span>')}
</table>

<h2>🦠 Amenazas JS</h2>
{jst_html}

<h2>⚙️ Stack Tecnológico</h2>
{"<table><tr><th>Componente</th><th>Valor</th></tr>" + stack_rows + "</table>" if stack_rows else "<p style='color:#8b949e'>No detectado</p>"}

<h2>👤 Usuarios Enumerados ({s.get("users_found",0)})</h2>
{"<table><tr><th>ID</th><th>Login</th><th>Nombre</th><th>Fuente</th></tr>" + users_rows + "</table>" if users_rows else "<p style='color:#2ed573'>✓ Sin usuarios enumerables</p>"}

<footer>
  Generado por <strong>WP VulnScanner v5.4</strong> · {now_str}<br>
  Este informe es confidencial. Solo para uso con autorización expresa del propietario del sistema auditado.
</footer>
</body>
</html>"""

    return html.encode("utf-8")

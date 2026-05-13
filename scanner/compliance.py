"""
WP VulnScanner — Compliance Mapper v1.0
============================================
Mapea automáticamente los hallazgos del escáner a requisitos específicos de:
  - GDPR (EU 2016/679)
  - PCI-DSS v4.0
  - OWASP Top 10 2021
  - ISO 27001:2022

Devuelve un informe de cumplimiento que indica qué artículos/controles
están en riesgo basándose en los hallazgos reales del escaneo.
Ningún otro escáner WordPress hace esto.
"""

from __future__ import annotations


                                                                               
                                      
                                                                               

FRAMEWORKS = {
    "gdpr": {
        "name": "GDPR",
        "full_name": "Reglamento General de Protección de Datos (EU 2016/679)",
        "color": "#2b7fff",
        "controls": {
            "Art.5(1)(f)": "Integridad y confidencialidad — los datos deben protegerse contra acceso no autorizado",
            "Art.25":      "Privacidad por diseño y por defecto — medidas técnicas adecuadas desde el diseño",
            "Art.32":      "Seguridad del tratamiento — medidas técnicas y organizativas apropiadas",
            "Art.33":      "Notificación de brechas — obligación de notificar en 72h si hay incidente",
            "Art.83(4)":   "Sanción: hasta 10M€ o 2% facturación global por incumplimiento Art.32",
            "Art.83(5)":   "Sanción: hasta 20M€ o 4% facturación global por infracciones graves",
        },
    },
    "pci_dss": {
        "name": "PCI-DSS",
        "full_name": "Payment Card Industry Data Security Standard v4.0",
        "color": "#f5a31a",
        "controls": {
            "Req.2.2":  "Configuración segura de todos los componentes del sistema",
            "Req.4.2":  "Los datos de titulares de tarjeta deben cifrarse en tránsito",
            "Req.6.2":  "Todos los componentes del sistema protegidos de vulnerabilidades conocidas",
            "Req.6.3":  "Las vulnerabilidades de seguridad se identifican y abordan",
            "Req.6.4":  "Aplicaciones web protegidas contra ataques conocidos",
            "Req.7.2":  "Acceso a componentes del sistema restringido según necesidad",
            "Req.8.3":  "Autenticación de usuarios y administradores asegurada",
            "Req.10.7": "Fallos en controles de seguridad detectados y reportados",
            "Req.11.3": "Vulnerabilidades externas e internas gestionadas",
            "Req.12.3": "Riesgos de seguridad identificados, evaluados y gestionados",
        },
    },
    "owasp": {
        "name": "OWASP Top 10",
        "full_name": "OWASP Top 10 — 2021",
        "color": "#00c8c0",
        "controls": {
            "A01:2021": "Broken Access Control — Control de acceso roto",
            "A02:2021": "Cryptographic Failures — Fallos criptográficos",
            "A03:2021": "Injection — Inyección (SQL, XSS, etc.)",
            "A04:2021": "Insecure Design — Diseño inseguro",
            "A05:2021": "Security Misconfiguration — Mala configuración de seguridad",
            "A06:2021": "Vulnerable and Outdated Components — Componentes vulnerables o desactualizados",
            "A07:2021": "Identification and Authentication Failures — Fallos de autenticación",
            "A08:2021": "Software and Data Integrity Failures — Fallos de integridad",
            "A09:2021": "Security Logging and Monitoring Failures — Fallos de monitorización",
            "A10:2021": "Server-Side Request Forgery (SSRF)",
        },
    },
    "iso27001": {
        "name": "ISO 27001",
        "full_name": "ISO/IEC 27001:2022",
        "color": "#9b59b6",
        "controls": {
            "A.8.8":   "Gestión de vulnerabilidades técnicas",
            "A.8.9":   "Gestión de la configuración",
            "A.8.20":  "Seguridad de redes",
            "A.8.21":  "Seguridad de servicios de red",
            "A.8.22":  "Segregación de redes",
            "A.8.23":  "Filtrado web",
            "A.8.25":  "Ciclo de vida de desarrollo seguro",
            "A.8.28":  "Codificación segura",
            "A.8.29":  "Pruebas de seguridad en desarrollo y aceptación",
            "A.5.14":  "Transferencia de información segura",
            "A.5.33":  "Protección de registros",
            "A.6.8":   "Reporte de eventos de seguridad de la información",
        },
    },
}


                                                                               
                                                                                     
                                                                               

def _build_findings(scan_result: dict) -> list[dict]:
    """
    Analiza el resultado del escáner y genera una lista de hallazgos
    mapeados a controles de cumplimiento.
    """
    findings: list[dict] = []
    def add(framework: str, control: str, risk: str, sev: str, detail: str = ""):
        findings.append({
            "framework": framework,
            "control":   control,
            "risk":      risk,
            "severity":  sev,
            "detail":    detail,
        })

                                                                               
    vulns_raw = scan_result.get("vulnerabilities", [])
    vulns = [v for v in (vulns_raw or []) if isinstance(v, dict)]
    crit_vulns  = [v for v in vulns if v.get("severity") == "critical"]
    kev_vulns   = [v for v in vulns if v.get("kev")]

    if vulns:
        add("pci_dss", "Req.6.3", "Vulnerabilidades conocidas sin remediar", "high",
            f"{len(vulns)} vulnerabilidades detectadas ({len(crit_vulns)} críticas)")
        add("owasp", "A06:2021", "Componentes vulnerables instalados", "high",
            f"{len(vulns)} CVEs activos en plugins/temas/core")
        add("iso27001", "A.8.8", "Gestión de vulnerabilidades incompleta", "medium",
            f"Actualizar componentes afectados por {len(vulns)} CVEs")

    if crit_vulns:
        add("gdpr", "Art.32", "Riesgo de brecha de datos por vulnerabilidades críticas", "critical",
            f"{len(crit_vulns)} vulnerabilidades críticas que pueden comprometer datos personales")
        add("pci_dss", "Req.11.3", "Vulnerabilidades críticas sin mitigar", "critical",
            f"CVEs críticos: {', '.join(v.get('cve_id','?') for v in crit_vulns[:3])}")

    if kev_vulns:
        add("gdpr", "Art.33", "Vulnerabilidades en explotación activa — riesgo de brecha notificable", "critical",
            f"{len(kev_vulns)} CVEs en catálogo CISA KEV (explotados activamente)")
        add("pci_dss", "Req.10.7", "Componentes con exploits activos en wild", "critical",
            "CISA KEV confirma explotación activa. Respuesta inmediata requerida.")

                                                                                
    ssl = scan_result.get("ssl_info") or {}
    tls = scan_result.get("tls_analysis") or {}

    if ssl.get("expired") or not ssl.get("valid"):
        add("pci_dss", "Req.4.2", "Certificado SSL inválido o expirado", "critical",
            "Datos en tránsito sin cifrado válido — incumplimiento directo PCI-DSS 4.2")
        add("gdpr", "Art.32", "Transmisión de datos sin cifrado adecuado", "critical",
            "Art.32(1)(a) exige cifrado apropiado de datos personales en tránsito")
        add("owasp", "A02:2021", "Fallo criptográfico — SSL inválido", "critical")

    if tls.get("deprecated_protocol"):
        protos = ", ".join(tls.get("weak_protocol_list", ["TLS 1.0/1.1"]))
        add("pci_dss", "Req.4.2", f"Protocolo TLS obsoleto activo: {protos}", "high",
            "PCI-DSS 4.0 requiere TLS 1.2 mínimo. TLS 1.0/1.1 prohibidos desde 2020.")
        add("owasp", "A02:2021", f"Cifrado débil — {protos} activo", "high")
        add("iso27001", "A.5.14", "Transferencia insegura por protocolo obsoleto", "high")

    if tls.get("weak_cipher"):
        add("pci_dss", "Req.4.2", "Cipher suites débiles habilitadas", "high")
        add("iso27001", "A.8.20", "Configuración criptográfica de red inadecuada", "medium")

                                                                                
    hdr_issues = scan_result.get("headers_issues", [])
    if len(hdr_issues) >= 3:
        add("owasp", "A05:2021", f"{len(hdr_issues)} cabeceras de seguridad ausentes", "medium",
            "X-Frame-Options, CSP, HSTS, etc. — configuración de seguridad incompleta")
        add("pci_dss", "Req.2.2", "Servidor sin cabeceras de seguridad básicas", "medium")

    csp = scan_result.get("csp_analysis") or {}
    if not csp.get("present"):
        add("owasp", "A05:2021", "Content-Security-Policy ausente — XSS sin mitigar", "medium")
    elif csp.get("unsafe_inline"):
        add("owasp", "A03:2021", "CSP con unsafe-inline — protección XSS comprometida", "medium")

    hsts = scan_result.get("hsts_analysis") or {}
    if not hsts.get("present"):
        add("pci_dss", "Req.4.2", "HSTS ausente — HTTPS no se fuerza a clientes", "medium")

                                                                                
    users_raw = scan_result.get("users", [])
    users = [u for u in (users_raw or []) if isinstance(u, dict)]
    if users:
        add("gdpr", "Art.5(1)(f)", f"{len(users)} nombres de usuario expuestos públicamente", "high",
            "La enumeración de usuarios facilita ataques dirigidos a datos personales")
        add("pci_dss", "Req.7.2", "Información de usuarios accesible sin autenticación", "high")
        add("owasp", "A07:2021", "Enumeración de usuarios — información de autenticación expuesta", "medium")

                                                                                
    exposed_raw = scan_result.get("exposed_files", [])
    exposed = [f for f in (exposed_raw or []) if isinstance(f, dict)]
    crit_files = [f for f in exposed if f.get("severity") == "critical"]
    if crit_files:
        add("gdpr", "Art.32", f"{len(crit_files)} archivos críticos accesibles (wp-config, .env, dumps SQL)", "critical",
            "Credenciales de BD y datos personales potencialmente expuestos")
        add("pci_dss", "Req.6.4", "Archivos de configuración expuestos al público", "critical")
        add("owasp", "A05:2021", "Configuración sensible accesible desde internet", "critical")
        add("iso27001", "A.8.9", "Gestión de configuración fallida — archivos sensibles accesibles", "critical")

    if any("git" in (f.get("path") or "").lower() for f in exposed):
        add("owasp", "A08:2021", "Repositorio Git expuesto — riesgo de integridad de código", "critical")
        add("iso27001", "A.8.25", "Código fuente accesible — ciclo de vida de desarrollo comprometido", "critical")

                                                                                
    rest = scan_result.get("rest_api_issues") or {}
    if rest.get("exposes_emails"):
        add("gdpr", "Art.5(1)(f)", "REST API expone emails de usuarios sin autenticación", "high",
            "Art.5(1)(f) — datos personales (emails) accesibles sin control de acceso")
        add("gdpr", "Art.25", "Sin privacidad por defecto — emails expuestos por configuración", "high")
        add("owasp", "A01:2021", "Control de acceso roto — datos personales sin proteger", "high")

    if rest.get("allows_edit_context"):
        add("pci_dss", "Req.7.2", "REST API permite acceso a contenido sin autenticación", "critical")
        add("owasp", "A01:2021", "Broken Access Control en REST API", "critical")

                                                                                
    lp = scan_result.get("login_protection") or {}
    deep = scan_result.get("deep_scan") or {}
    login_sec = deep.get("login_security") or {}

    if lp.get("no_lockout_detected") or not login_sec.get("rate_limit_detected"):
        add("pci_dss", "Req.8.3", "wp-login.php sin protección anti-fuerza bruta", "high",
            "PCI-DSS 8.3.4 requiere bloqueo tras máx. 10 intentos fallidos")
        add("owasp", "A07:2021", "Sin rate limiting en autenticación — fuerza bruta posible", "high")
        add("iso27001", "A.8.28", "Mecanismo de autenticación inseguro", "medium")

                                                                                
    debug = scan_result.get("debug_mode") or {}
    if debug.get("debug_active"):
        add("owasp", "A05:2021", "WP_DEBUG activo en producción — información de sistema expuesta", "high")
        add("pci_dss", "Req.6.4", "Modo debug activo — mensajes de error con información interna", "high")
        add("iso27001", "A.5.33", "Logs de depuración expuestos públicamente", "medium")

                                                                               
    cors = scan_result.get("cors_issues") or {}
    if cors.get("vulnerable"):
        add("owasp", "A05:2021", f"CORS misconfiguration — {cors.get('severity','?')}", "high")
        add("iso27001", "A.8.22", "Política de origen cruzado incorrecta", "medium")

                                                                                
    if scan_result.get("xmlrpc_enabled"):
        add("pci_dss", "Req.2.2", "XML-RPC activo — superficie de ataque innecesaria", "medium",
            "Vector de fuerza bruta y amplificación DDoS. Deshabilitar si no es necesario.")
        add("owasp", "A10:2021", "XML-RPC — vector potencial de SSRF", "medium")

                                                                                
    rep = scan_result.get("reputation") or {}
    malware = scan_result.get("malware_indicators") or []

    if rep.get("risk_level") == "malicious":
        add("gdpr", "Art.33", "Dominio en listas negras — posible brecha en curso", "critical",
            "Indicios de compromiso activo. Evaluar notificación a autoridad de control (72h).")
        add("pci_dss", "Req.10.7", "Sistema potencialmente comprometido — en lista negra", "critical")

    if malware:
        add("gdpr", "Art.33", f"{len(malware)} indicadores de malware detectados", "critical",
            "Posible acceso no autorizado a datos. Obligación de notificación puede aplicar.")
        add("owasp", "A08:2021", f"Indicadores de compromiso — {len(malware)} hallazgos", "critical")

    return findings


def _aggregate_by_framework(findings: list[dict]) -> dict:
    """Agrupa hallazgos por framework y calcula estado de cumplimiento."""
    result = {}

    for fw_id, fw_info in FRAMEWORKS.items():
        fw_findings = [f for f in findings if f["framework"] == fw_id]

                                      
        if any(f["severity"] == "critical" for f in fw_findings):
            status = "critical"
            status_label = "INCUMPLIMIENTO GRAVE"
        elif any(f["severity"] == "high" for f in fw_findings):
            status = "high"
            status_label = "RIESGO ALTO"
        elif any(f["severity"] == "medium" for f in fw_findings):
            status = "medium"
            status_label = "ATENCIÓN REQUERIDA"
        elif fw_findings:
            status = "low"
            status_label = "RIESGO BAJO"
        else:
            status = "ok"
            status_label = "SIN HALLAZGOS"

                             
        controls_at_risk = list({f["control"] for f in fw_findings})

        result[fw_id] = {
            "name":             fw_info["name"],
            "full_name":        fw_info["full_name"],
            "color":            fw_info["color"],
            "status":           status,
            "status_label":     status_label,
            "findings_count":   len(fw_findings),
            "controls_at_risk": controls_at_risk,
            "findings":         fw_findings,
            "controls_desc":    fw_info["controls"],
        }

    return result


def map_compliance(scan_result: dict) -> dict:
    """
    Punto de entrada principal del módulo.
    Devuelve un dict con:
      - by_framework: dict por framework con hallazgos y estado
      - total_findings: int
      - critical_frameworks: list[str]
      - summary_table: list[dict] para renderizar en la UI
    """
    findings = _build_findings(scan_result)
    by_framework = _aggregate_by_framework(findings)

    critical_frameworks = [
        fw for fw, data in by_framework.items()
        if data.get("status") == "critical"
    ]

    summary_table = [
        {
            "id":     fw_id,
            "name":   data["name"],
            "color":  data["color"],
            "status": data.get("status", "ok"),
            "label":  data.get("status_label", ""),
            "count":  data.get("findings_count", 0),
        }
        for fw_id, data in by_framework.items()
    ]

    return {
        "by_framework":       by_framework,
        "total_findings":     len(findings),
        "critical_frameworks": critical_frameworks,
        "summary_table":      summary_table,
    }

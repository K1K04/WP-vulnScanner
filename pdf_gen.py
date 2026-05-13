"""
pdf_gen.py — Generación de PDF técnico para WP VulnScanner
"""
from __future__ import annotations
import io
import logging
log = logging.getLogger("wpvulnscan.pdf")

def generate_pdf(result: dict) -> bytes:
    from xml.sax.saxutils import escape as _xml_esc                                          
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, HRFlowable,
                                    KeepTogether)
    from reportlab.graphics.shapes import Drawing, Rect, String

    PAGE_W, PAGE_H = A4
    MARGIN = 1.8 * cm

                                                                              
    C = {
        "bg":      colors.HexColor("#ffffff"),                           
        "bg2":     colors.HexColor("#f8f9fa"),                      
        "bg3":     colors.HexColor("#f0f2f5"),                  
        "border":  colors.HexColor("#d4d4d4"),                        
        "border2": colors.HexColor("#e0e0e0"),                        
        "green":   colors.HexColor("#1f7a34"),                                   
        "green2":  colors.HexColor("#28a745"),                   
        "cyan":    colors.HexColor("#0066cc"),                        
        "red":     colors.HexColor("#c1272d"),                        
        "orange":  colors.HexColor("#ff8c00"),                           
        "yellow":  colors.HexColor("#ff9800"),                            
        "text":    colors.HexColor("#1a1a1a"),                                    
        "text2":   colors.HexColor("#666666"),                                 
        "text3":   colors.HexColor("#999999"),                  
        "white":   colors.white,
    }
    SEV_C = {
        "critical": C["red"], "high": C["orange"],
        "medium": C["yellow"], "low": C["green2"], "info": C["cyan"],
    }

    risk = result.get("risk_score", 0)
    rlabel = result.get("risk_label", "BAJO")
    risk_color = (C["red"] if risk >= 70 else C["orange"] if risk >= 45
                  else C["yellow"] if risk >= 20 else C["green2"])

    s = result.get("summary", {})

                                                                               
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=MARGIN,
        title=f"WPVulnScanner — {result.get('target_url','')}",
        author="WP VulnScanner",
        subject="Informe de Auditoría de Seguridad WordPress",
    )

                                                                               
    base = getSampleStyleSheet()
    CW = (PAGE_W - 2 * MARGIN)

    def S(name, **kw):
        kw.setdefault("fontName", "Helvetica")
        return ParagraphStyle(name, parent=base["Normal"], **kw)

    ST = {
        "h_title":  S("ht",  fontSize=26, textColor=C["green"],  fontName="Helvetica-Bold", leading=32, spaceAfter=8),
        "h_sub":    S("hs",  fontSize=10, textColor=C["text2"],  leading=14, spaceAfter=12),
        "section":  S("sec", fontSize=14, textColor=C["cyan"],   fontName="Helvetica-Bold",
                      spaceBefore=18, spaceAfter=10, borderPad=4),
        "subsec":   S("sub", fontSize=11, textColor=C["green"],  fontName="Helvetica-Bold",
                      spaceBefore=12, spaceAfter=6),
        "body":     S("b",   fontSize=9.5, textColor=C["text"],   leading=14),
        "small":    S("sm",  fontSize=8,   textColor=C["text2"],  leading=12),
        "label":    S("lb",  fontSize=8,   textColor=C["text2"],  fontName="Helvetica-Bold",
                      textTransform="uppercase"),
        "value":    S("vl",  fontSize=9,   textColor=C["text"],   leading=13),
        "warn":     S("wn",  fontSize=9,   textColor=C["orange"], fontName="Helvetica-Bold"),
        "crit":     S("cr",  fontSize=9,   textColor=C["red"],    fontName="Helvetica-Bold"),
        "ok":       S("ok",  fontSize=9,   textColor=C["green2"], fontName="Helvetica-Bold"),
        "fix":      S("fx",  fontSize=8.5, textColor=C["green2"]),
        "legal":    S("lg",  fontSize=7,   textColor=C["text3"],  leading=10),
        "code":     S("cd",  fontSize=8,   textColor=C["cyan"],   fontName="Courier-Bold"),
        "tag":      S("tg",  fontSize=7.5, textColor=C["text2"],  fontName="Helvetica"),
    }

    story = []

                                                                               
             
                                                                               
    def make_cover():
        elems = []

                                  
        banner = Drawing(CW, 3.5 * cm)
        banner.add(Rect(0, 0, CW, 3.5 * cm, fillColor=C["bg2"], strokeColor=C["border"], strokeWidth=0.5))
        banner.add(Rect(0, 3.5 * cm - 3, CW, 3, fillColor=C["green"], strokeColor=None))

                            
        logo_x_offset = 20
        try:
            import os as _os
            from reportlab.platypus import Image as _RLImage
            logo_path = _os.path.join(_os.path.dirname(__file__), "static", "logo.png")
            if _os.path.exists(logo_path):
                from reportlab.graphics.shapes import Image as _SVGImg
                                                             
                from PIL import Image as _PILImg
                import io as _io
                _pil = _PILImg.open(logo_path).convert("RGBA")
                _pil = _pil.resize((40, 40), _PILImg.LANCZOS)
                _buf2 = _io.BytesIO()
                _pil.save(_buf2, "PNG")
                _buf2.seek(0)
                from reportlab.graphics.shapes import Image as _GImg
                _gimg = _GImg(20, 0.9 * cm, 38, 38, _buf2.read())
                banner.add(_gimg)
                logo_x_offset = 68
        except Exception as _e:
            try:
                log = globals().get("log")
                if log:
                    log.debug("pdf_gen logo processing suppressed: %s", _e)
            except Exception:
                pass

        banner.add(String(logo_x_offset, 1.8 * cm, "WP VulnScanner",
                          fontName="Helvetica-Bold", fontSize=20, fillColor=C["green"]))
        banner.add(String(logo_x_offset, 0.9 * cm, "Informe de Auditoría de Seguridad WordPress",
                          fontName="Helvetica", fontSize=10, fillColor=C["text2"]))
        elems.append(banner)
        elems.append(Spacer(1, 0.4 * cm))

                                         
        target_url = result.get("target_url", "")
        meta = [
            ("🎯  Objetivo",   target_url),
            ("🔑  Scan ID",    result.get("scan_id", result.get("id", "—"))),
            ("📅  Fecha",      result.get("scanned_at", "—")),
            ("⏱  Duración",   f"{result.get('duration', 0)}s"),
            ("⚙  Motor",      "WPScan API (tiempo real)" if result.get("wpscan_api_used") else "Base de datos offline"),
        ]
        if result.get("legal_accepted"):
            meta.append(("✅  Autorización", "Declarada — IP registrada"))

        meta_rows = [[
            Paragraph(k, ST["label"]),
            Paragraph(str(v), ST["value"]),
        ] for k, v in meta]

        mt = Table(meta_rows, colWidths=[3.2 * cm, CW - 3.2 * cm])
        mt.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C["bg3"]),
            ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C["white"], C["bg2"]]),
            ("BOX",           (0, 0), (-1, -1), 0.5, C["border"]),
            ("GRID",          (0, 0), (-1, -1), 0.3, C["border2"]),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("TEXTCOLOR",     (0, 0), (0, -1), C["cyan"]),
            ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elems.append(mt)
        elems.append(Spacer(1, 0.8 * cm))

                                                                               
        gauge_w, gauge_h = CW, 4.2 * cm
        gauge = Drawing(gauge_w, gauge_h)

                             
        gauge.add(Rect(0, 0, gauge_w, gauge_h,
                       fillColor=C["bg3"], strokeColor=risk_color, strokeWidth=2))

                                                
        bar_x, bar_y, bar_h = 0.6 * cm, 0.7 * cm, 0.6 * cm
        bar_full_w = gauge_w - 1.2 * cm
        gauge.add(Rect(bar_x, bar_y, bar_full_w, bar_h,
                       fillColor=C["border2"], strokeColor=C["border"], strokeWidth=0.5))
        gauge.add(Rect(bar_x, bar_y, bar_full_w * risk / 100, bar_h,
                       fillColor=risk_color, strokeColor=None))

                                     
        gauge.add(String(1.2 * cm, 2.0 * cm, str(risk),
                         fontName="Helvetica-Bold", fontSize=40, fillColor=risk_color))
        gauge.add(String(1.2 * cm + (3 if risk < 10 else 5 if risk < 100 else 6.5) * 0.65 * cm,
                         2.6 * cm, "/100",
                         fontName="Helvetica", fontSize=13, fillColor=C["text2"]))

                                  
        gauge.add(String(1.2 * cm, 1.35 * cm, rlabel,
                         fontName="Helvetica-Bold", fontSize=15, fillColor=risk_color))
        gauge.add(String(1.2 * cm, 0.92 * cm, "Puntuación de riesgo global",
                         fontName="Helvetica", fontSize=8.5, fillColor=C["text2"]))

                                           
        stats_x = 5.8 * cm
        gauge.add(String(stats_x, 3.1 * cm,
                         f"● {s.get('critical_vulns',0)} críticas",
                         fontName="Helvetica-Bold", fontSize=9, fillColor=C["red"]))
        gauge.add(String(stats_x, 2.65 * cm,
                         f"● {s.get('high_vulns',0)} altas",
                         fontName="Helvetica-Bold", fontSize=9, fillColor=C["orange"]))
        gauge.add(String(stats_x, 2.2 * cm,
                         f"● {s.get('vulns_found',0)} vulnerabilidades totales",
                         fontName="Helvetica", fontSize=8, fillColor=C["text"]))
        gauge.add(String(stats_x, 1.75 * cm,
                         f"● {s.get('plugins_found',0)} plugins · {s.get('themes_found',0)} temas",
                         fontName="Helvetica", fontSize=8, fillColor=C["text2"]))
        gauge.add(String(stats_x, 1.3 * cm,
                         f"● {s.get('exposed_files',0)} archivos expuestos",
                         fontName="Helvetica", fontSize=8, fillColor=C["text2"]))
        gauge.add(String(stats_x, 0.85 * cm,
                         f"● {s.get('users_found',0)} usuarios enumerados",
                         fontName="Helvetica", fontSize=8, fillColor=C["text2"]))

        elems.append(gauge)
        elems.append(Spacer(1, 0.3 * cm))

                                              
        extras = []
        if result.get("xmlrpc_enabled"):
            extras.append(("⚠ XML-RPC ACTIVO", C["orange"]))
        if result.get("wp_outdated"):
            extras.append((f"⚠ WP DESACTUALIZADO ({result.get('wp_version')} → {result.get('wp_latest_version')})", C["orange"]))
        if result.get("login_exposed"):
            extras.append(("⚠ /wp-login.php EXPUESTO", C["yellow"]))
        ssl = result.get("ssl_info") or {}
        if ssl.get("expired"):
            extras.append(("⚠ CERTIFICADO SSL EXPIRADO", C["red"]))

        if extras:
            for txt, col in extras:
                elems.append(Paragraph(txt, ParagraphStyle("ex", parent=base["Normal"],
                    fontSize=8.5, textColor=col, spaceBefore=2)))
        elems.append(Spacer(1, 0.5 * cm))
        return elems

    story.extend(make_cover())

                                                                               
                                           
                                                                               
    def sec_header(title: str, count: int | None = None):
        count_str = f"  ({count})" if count is not None else ""
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(f"{title}{count_str}", ST["section"]))
        story.append(HRFlowable(width="100%", thickness=0.5, color=C["cyan"], spaceAfter=5))

                                                                               
                       
                                                                               
    sec_header("Información del Sitio")
    ssl = result.get("ssl_info") or {}

    def ssl_txt():
        if not ssl:
            return "No analizado"
        if ssl.get("error") and not ssl.get("valid"):
            return f"⚠ Error: {ssl.get('error','')[:60]}"
        if ssl.get("expired"):
            return "❌ EXPIRADO"
        dl = ssl.get("days_left", 0)
        col_label = "ADVERTENCIA" if dl < 30 else "OK"
        return f"✓ {dl}d restantes [{col_label}] · Emisor: {ssl.get('issuer','?')}"

    info_data = [
        ("WordPress",   f"{'Detectado ✓' if result.get('is_wordpress') else '? No confirmado'}"),
        ("Versión WP",  f"{result.get('wp_version') or 'No detectada'}"
                        f"{' ⚠ DESACTUALIZADO → ' + str(result.get('wp_latest_version','')) if result.get('wp_outdated') else ''}"),
        ("Servidor",    result.get("server_info") or "Oculto ✓"),
        ("PHP",         result.get("php_version") or "Oculta ✓"),
        ("XML-RPC",     "⚠ ACTIVO" if result.get("xmlrpc_enabled") else "✓ Desactivado"),
        ("Login WP",    "⚠ Accesible" if result.get("login_exposed") else "✓ Protegido"),
        ("SSL/HTTPS",   ssl_txt()),
        ("Motor vulns", "⚡ WPScan API (tiempo real)" if result.get("wpscan_api_used") else "📦 Base de datos offline"),
    ]

    info_rows = [[Paragraph(k, ST["label"]), Paragraph(v, ST["value"])] for k, v in info_data]
    info_table = Table(info_rows, colWidths=[3.5 * cm, CW - 3.5 * cm])
    info_table.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C["white"], C["bg2"]]),
        ("BOX",            (0, 0), (-1, -1), 0.5, C["border"]),
        ("GRID",           (0, 0), (-1, -1), 0.3, C["border2"]),
        ("LEFTPADDING",    (0, 0), (-1, -1), 9),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 9),
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
        ("TEXTCOLOR",      (0, 0), (0, -1), C["cyan"]),
        ("FONTNAME",       (0, 0), (0, -1), "Helvetica-Bold"),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 0.4 * cm))

                                                                               
                         
                                                                               
    vulns = result.get("vulnerabilities", [])
    sec_header("Vulnerabilidades", len(vulns))

    if not vulns:
        story.append(Paragraph("✓ No se encontraron vulnerabilidades conocidas.", ST["ok"]))
    else:
                                     
        sev_counts = {}
        for v in vulns:
            if isinstance(v, dict):
                sev_counts[v.get("severity","medium")] = sev_counts.get(v.get("severity","medium"), 0) + 1

        sev_summary_data = [
            [Paragraph(sev.upper(), ParagraphStyle("sv", parent=base["Normal"],
                       fontSize=8.5, textColor=SEV_C.get(sev, C["text2"]), fontName="Helvetica-Bold")),
             Paragraph(str(cnt), ParagraphStyle("sc", parent=base["Normal"],
                       fontSize=12, textColor=SEV_C.get(sev, C["text2"]), fontName="Helvetica-Bold")),
             ] for sev, cnt in sorted(sev_counts.items(),
                key=lambda x: ["critical","high","medium","low","info"].index(x[0]) if x[0] in ["critical","high","medium","low","info"] else 99)
        ]
        if sev_summary_data:
            cols = len(sev_summary_data)
            sev_table = Table([list(sum(sev_summary_data, []))],
                              colWidths=[CW / (cols * 2)] * (cols * 2))
            sev_table.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), C["bg3"]),
                ("BOX",          (0, 0), (-1, -1), 0.5, C["border"]),
                ("GRID",         (0, 0), (-1, -1), 0.3, C["border2"]),
                ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
                ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",   (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
            ]))
            story.append(sev_table)
            story.append(Spacer(1, 0.3 * cm))

                                      
        for v in vulns:
            if not isinstance(v, dict):
                continue
            sev = v.get("severity", "medium")
            sc  = SEV_C.get(sev, C["text2"])
            type_icon = {"wordpress": "WP", "theme": "TEMA", "plugin": "PLUGIN"}.get(v.get("type", "plugin"), "PLUGIN")

                            
            tags = [type_icon, v.get("plugin_slug", "")]
            if v.get("plugin_version"):
                tags.append(f"v{v['plugin_version']}")
            if v.get("cvss_score"):
                tags.append(f"CVSS {v['cvss_score']}")
            if v.get("cve_id"):
                tags.append(v["cve_id"])

            action_text = v.get("recommended_action") or (f"✓ Actualizar a v{v['fixed_in']}" if v.get("fixed_in") else "⚠ Sin fix conocido — considerar desactivar")
            action_style = ST["fix"] if v.get("fixed_in") or v.get("recommended_action") else ST["warn"]

            inner = Table([[
                Paragraph(sev.upper(), ParagraphStyle("sv2", parent=base["Normal"],
                           fontSize=8, textColor=sc, fontName="Helvetica-Bold")),
                [
                    Paragraph(f"<b>{_xml_esc(v.get('title',''))}</b>", ST["body"]),
                    Paragraph("  ".join(tags), ST["tag"]),
                    Paragraph(action_text, action_style),
                ],
            ]], colWidths=[1.8 * cm, CW - 1.8 * cm])
            inner.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), C["bg3"]),
                ("BOX",           (0, 0), (-1, -1), 0.5, sc),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                ("TOPPADDING",    (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LINEAFTER",     (0, 0), (0, -1), 3, sc),
                ("LINEBEFORE",    (0, 0), (0, -1), 0.5, sc),
                ("LINEBELOW",     (0, 0), (-1, -1), 0.3, C["border"]),
                ("LINEABOVE",     (0, 0), (-1, 0), 0.3, C["border"]),
            ]))
            story.append(KeepTogether([inner, Spacer(1, 0.25 * cm)]))

                                                                               
                                      
                                                                               
    plugins = result.get("plugins", [])
    themes  = result.get("themes", [])
    if plugins or themes:
        sec_header("Componentes detectados", len(plugins) + len(themes))

        outdated_total = s.get("outdated_plugins", 0) + s.get("outdated_themes", 0)
        if outdated_total:
            story.append(Paragraph(
                f"⚠ {outdated_total} componentes desactualizados — actualizar con urgencia", ST["warn"]))
            story.append(Spacer(1, 0.2 * cm))

        comp_header = [
            [Paragraph(h, ST["label"]) for h in ["Tipo", "Slug", "Instalada", "Última", "Estado"]]
        ]
        comp_rows = []
        for p in plugins + themes:
            if not isinstance(p, dict):
                continue
            is_out = p.get("is_outdated", False)
            ptype  = p.get("type", "plugin")
            comp_rows.append([
                Paragraph("Plugin" if ptype == "plugin" else "Tema", ST["small"]),
                Paragraph(p.get("slug", ""), ST["body"]),
                Paragraph(p.get("version") or "?", ST["small"]),
                Paragraph(p.get("latest_version") or "—", ST["small"]),
                Paragraph(
                    "⚠ DESACT." if is_out else "✓ OK",
                    ParagraphStyle("cs", parent=base["Normal"], fontSize=8,
                                   textColor=C["yellow"] if is_out else C["green2"])
                ),
            ])

        comp_table = Table(
            comp_header + comp_rows,
            colWidths=[1.8 * cm, 6.5 * cm, 2.5 * cm, 2.5 * cm, 2.2 * cm]
        )
        comp_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C["bg"]),
            ("TEXTCOLOR",     (0, 0), (-1, 0), C["white"]),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C["white"], C["bg2"]]),
            ("BOX",           (0, 0), (-1, -1), 0.5, C["border"]),
            ("GRID",          (0, 0), (-1, -1), 0.3, C["border2"]),
            ("LEFTPADDING",   (0, 0), (-1, -1), 7),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 7),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(comp_table)

                                                                               
                           
                                                                               
    exposed = result.get("exposed_files", [])
    sec_header("Archivos sensibles expuestos", len(exposed))

    if not exposed:
        story.append(Paragraph("✓ No se encontraron archivos sensibles expuestos.", ST["ok"]))
    else:
        for f in exposed:
            if isinstance(f, str):
                f = {"path": f, "description": "", "severity": "high", "extra": ""}
            if not isinstance(f, dict):
                continue
            sev = f.get("severity", "high")
            sc  = SEV_C.get(sev, C["orange"])
            extra_txt = f"  ⚠ {f['extra']}" if f.get("extra") else ""
            story.append(Paragraph(
                f"<font color='{sc.hexval()}'><b>[{sev.upper()}]</b></font>  "
                f"<font name='Courier' size='8'>{_xml_esc(f.get('path',''))}</font>  "
                f"— {_xml_esc(f.get('description',''))}{_xml_esc(extra_txt)}",
                ST["body"]
            ))

                                                                               
                 
                                                                               
    users = result.get("users", [])
    if users:
        sec_header("Usuarios expuestos", len(users))
        story.append(Paragraph(
            "⚠ Usuarios enumerados sin autenticación — facilitan ataques de fuerza bruta", ST["warn"]))
        story.append(Spacer(1, 0.2 * cm))
        for u in users:
            if not isinstance(u, dict):
                continue
            story.append(Paragraph(
                f"  ID {_xml_esc(str(u.get('id') or '?'))}  ·  Login: <b>{_xml_esc(u.get('login') or '?')}</b>"
                f"  ·  Nombre: {_xml_esc(u.get('display_name') or '?')}"
                f"  ·  Fuente: {_xml_esc(u.get('source') or '')}",
                ST["body"]
            ))

                                                                               
                
                                                                               
    malware = result.get("malware_indicators", [])
    if malware:
        sec_header("Indicadores de Malware / SEO Spam", len(malware))
        for m in malware:
            story.append(Paragraph(f"☣  {_xml_esc(str(m))}", ST["crit"]))

                                                                               
                               
                                                                               
    h_issues = result.get("headers_issues", [])
    h_ok     = result.get("headers_ok", [])
    sec_header(f"Cabeceras HTTP de seguridad  ({len(h_issues)} ausentes de 10)")

                               
    all_headers_data = (
        [(h, False) for h in h_issues] +
        [(h, True)  for h in h_ok]
    )
    for h, present in all_headers_data:
        icon  = "✓" if present else "✗"
        color = C["green2"] if present else C["red"]
        story.append(Paragraph(
            f"<font color='{color.hexval()}'><b>{icon}</b></font>  {h}",
            ST["body"]
        ))

                                                                               
                    
                                                                               
    if ssl and ssl.get("valid"):
        sec_header("Certificado SSL")
        dl = ssl.get("days_left", 0)
        sc = C["red"] if ssl.get("expired") else C["yellow"] if dl < 30 else C["green2"]
        story.append(Paragraph(
            f"<font color='{sc.hexval()}'><b>{'EXPIRADO' if ssl.get('expired') else f'Válido — {dl} días restantes'}</b></font>"
            f"  ·  Emisor: {ssl.get('issuer','?')}"
            f"  ·  Dominio: {ssl.get('subject','?')}",
            ST["body"]
        ))

                                                                               
                        
                                                                               
    errors = [e for e in (result.get("errors") or []) if not e.startswith("ℹ️")]
    if errors:
        sec_header("Notas del escaneo")
        for e in errors:
            story.append(Paragraph(f"ℹ  {_xml_esc(str(e))}", ST["small"]))

                                                                               
                                                                 
                                                                               
    ai_plan_text = result.get("ai_plan") or result.get("ai_remediation_plan", "")
    if ai_plan_text and str(ai_plan_text).strip():
        story.append(Spacer(1, 0.4 * cm))
        sec_header("Plan de Remediación — Análisis IA")

                                          
        import re as _re
        clean_plan = str(ai_plan_text)
                                                       
        for line in clean_plan.split("\n"):
            line = line.strip()
            if not line:
                story.append(Spacer(1, 0.15 * cm))
                continue
            if line.startswith("## "):
                story.append(Paragraph(_xml_esc(line[3:]), ST["label"]))
            elif line.startswith("- ") or line.startswith("• "):
                story.append(Paragraph(f"• {_xml_esc(line[2:])}", ST["small"]))
            else:
                                           
                line = _re.sub(r'\*\*(.+?)\*\*', r'\1', line)
                story.append(Paragraph(_xml_esc(line), ST["value"]))

                                                                               
                         
                                                                               
    story.append(Spacer(1, 0.6 * cm))
    story.append(HRFlowable(width="100%", thickness=0.4, color=C["text3"], spaceAfter=6))
    story.append(Paragraph(
        "Informe generado por WP VulnScanner · 2026.  "
        "Análisis externo y pasivo. El solicitante declara tener autorización expresa del propietario "
        "del sitio para realizar esta auditoría de seguridad (Art. 264 CP).",
        ST["legal"]
    ))

                                                                              
    def on_page(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 6.5)
        canvas.setFillColor(C["text3"])
        canvas.drawString(MARGIN, 0.8 * cm,
                          f"WP VulnScanner · {result.get('target_url','')} · {result.get('scanned_at','')}")
        canvas.drawRightString(PAGE_W - MARGIN, 0.8 * cm, f"Página {doc_.page}")
        canvas.restoreState()

                                                                       
                                                                                             
    try:
        doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    except Exception as _pdf_err:
        log.error("generate_pdf: error en doc.build(): %s", _pdf_err, exc_info=True)
                                                                       
        buf = io.BytesIO()
        _err_doc = SimpleDocTemplate(buf, pagesize=A4)
        _err_story = [
            Paragraph("Error generando el informe PDF completo.", ST["crit"]),
            Spacer(1, 0.3 * cm),
            Paragraph(f"Motivo: {_xml_esc(str(_pdf_err)[:200])}", ST["small"]),
            Spacer(1, 0.2 * cm),
            Paragraph("Usa la exportación HTML o Excel como alternativa.", ST["body"]),
        ]
        try:
            _err_doc.build(_err_story)
        except Exception:
            pass                                                           
    return buf.getvalue()


                                                                               
             
                                                                               


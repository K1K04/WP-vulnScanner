                      
"""
WP VulnScanner — CLI de Remediación con WP-CLI
===================================================
Lee los resultados del último escaneo (o un fichero JSON) y genera un
plan de remediación ejecutable con comandos WP-CLI listos para copiar/pegar
o ejecutar directamente en el servidor WordPress.

Uso:
  python wp_remediate.py                        # último escaneo de la BD
  python wp_remediate.py --url https://mi-wp.com # escaneo más reciente de esa URL
  python wp_remediate.py --file resultado.json   # desde fichero exportado
  python wp_remediate.py --run                   # ejecutar WP-CLI directamente
  python wp_remediate.py --wp-path /var/www/html # ruta al WordPress
  python wp_remediate.py --dry-run               # solo mostrar, no ejecutar
  python wp_remediate.py --output script.sh      # exportar como bash script
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))


                                                                                 
                     
                                                                                 

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"
    ORANGE = "\033[33m"

def _c(color: str, text: str, no_color: bool = False) -> str:
    if no_color or not sys.stdout.isatty():
        return text
    return f"{color}{text}{C.RESET}"

def ok(msg):   print(f"  {_c(C.GREEN, '✓')} {msg}")
def warn(msg): print(f"  {_c(C.YELLOW,'⚠')} {msg}")
def err(msg):  print(f"  {_c(C.RED,   '✗')} {msg}")
def info(msg): print(f"  {_c(C.BLUE,  '→')} {msg}")
def head(msg): print(f"\n{_c(C.BOLD, msg)}")
def sep():     print(_c(C.DIM, "─" * 68))


                                                                                 
                      
                                                                                 

@dataclass
class RemediationItem:
    category:    str                                                             
    priority:    int                                                  
    title:       str
    description: str
    commands:    list[str] = field(default_factory=list)
    verify_cmd:  str = ""
    manual_step: str = ""
    cve:         str = ""
    severity:    str = "medium"
    fixed_in:    str = ""
    plugin_slug: str = ""


PRIORITY_LABEL = {1: "🚨 INMEDIATA", 2: "⚡ ESTA SEMANA", 3: "📅 ESTE MES"}
PRIORITY_COLOR = {1: C.RED, 2: C.ORANGE, 3: C.YELLOW}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


                                                                                 
                     
                                                                                 

def load_result_from_db(url: Optional[str] = None) -> Optional[dict]:
    """Lee el escaneo más reciente de la BD de WP VulnScanner."""
    db_path = BASE_DIR / "scans.db"
    if not db_path.exists():
        err(f"BD no encontrada: {db_path}")
        err("Ejecuta un escaneo primero desde la interfaz web.")
        return None
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        if url:
            row = conn.execute(
                "SELECT result_json FROM scans WHERE url LIKE ? AND result_json IS NOT NULL "
                "ORDER BY scanned_at DESC LIMIT 1",
                (f"%{url}%",)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT result_json FROM scans WHERE result_json IS NOT NULL "
                "ORDER BY scanned_at DESC LIMIT 1"
            ).fetchone()
    finally:
        conn.close()

    if not row:
        err("No se encontraron escaneos en la BD.")
        return None
    try:
        return json.loads(row[0])
    except (json.JSONDecodeError, TypeError):
        err("Resultado de BD corrupto o vacío.")
        return None


def load_result_from_file(path: str) -> Optional[dict]:
    """Lee un JSON exportado por WP VulnScanner."""
    p = Path(path)
    if not p.exists():
        err(f"Fichero no encontrado: {path}")
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
                                                                               
        return data.get("result", data) if isinstance(data, dict) else None
    except (json.JSONDecodeError, Exception) as e:
        err(f"Error leyendo {path}: {e}")
        return None


                                                                                 
                                   
                                                                                 

def build_plan(result: dict, wp_path: str = "") -> list[RemediationItem]:
    """
    Analiza el resultado del escaneo y genera una lista ordenada de
    RemediationItem con comandos WP-CLI concretos.
    """
    plan: list[RemediationItem] = []
    wp   = f"--path={wp_path}" if wp_path else ""

    def wpcli(*parts: str) -> str:
        """Construye un comando wp-cli con path opcional."""
        cmd = " ".join(["wp"] + list(parts))
        return f"{cmd} {wp}".strip()

                                                                               
    if result.get("wp_outdated"):
        current = result.get("wp_version", "?")
        latest  = result.get("wp_latest_version", "?")
        plan.append(RemediationItem(
            category="core",
            priority=2,
            severity="high",
            title=f"WordPress Core desactualizado: {current} → {latest}",
            description=(
                f"Versión instalada {current} tiene vulnerabilidades conocidas. "
                f"La versión {latest} corrige estos problemas."
            ),
            commands=[
                "# Hacer backup antes de actualizar",
                wpcli("db", "export", "backup-pre-update.sql"),
                "# Actualizar WordPress Core",
                wpcli("core", "update"),
                wpcli("core", "update-db"),
                "# Verificar integridad de archivos core tras actualización",
                wpcli("core", "verify-checksums"),
            ],
            verify_cmd=wpcli("core", "version"),
        ))

                                                                                
    cve_specific = {
        "CVE-2023-32243": {
            "urgency": 1,
            "extra": [
                "# Auditar admins creados recientemente (posible compromiso)",
                wpcli("user", "list", "--role=administrator", "--orderby=registered", "--fields=ID,user_login,user_email,user_registered"),
                "# Forzar re-login de todos los usuarios como medida preventiva",
                wpcli("user", "session", "destroy", "--all"),
            ]
        },
        "CVE-2023-3460": {
            "urgency": 1,
            "extra": [
                "# CRÍTICO: Verificar usuarios admin creados en las últimas 2 semanas",
                wpcli("user", "list", "--role=administrator", "--fields=ID,user_login,user_email,user_registered"),
                "# Revisar logs de acceso por IPs desconocidas",
                "grep '/wp-admin' /var/log/nginx/access.log | tail -50",
            ]
        },
        "CVE-2024-10924": {
            "urgency": 1,
            "extra": [
                "# Bypass 2FA — forzar re-autenticación inmediata de todos",
                wpcli("user", "session", "destroy", "--all"),
            ]
        },
        "CVE-2023-28121": {
            "urgency": 1,
            "extra": [
                "# Revisar pedidos WooCommerce de usuarios anómalos",
                wpcli("post", "list", "--post_type=shop_order", "--posts_per_page=20", "--orderby=date", "--order=DESC"),
            ]
        },
    }

    vulns = sorted(
        [v for v in (result.get("vulnerabilities") or []) if isinstance(v, dict)],
        key=lambda v: SEV_ORDER.get(v.get("severity", "medium"), 9)
    )

                                                                         
    plugins_to_update: dict[str, dict] = {}
    for v in vulns:
        slug = v.get("plugin_slug") or v.get("component_slug", "")
        vtype = v.get("type", "plugin")
        if not slug or vtype == "wordpress":
            continue
        if slug not in plugins_to_update or SEV_ORDER.get(v.get("severity","medium"),9) < SEV_ORDER.get(plugins_to_update[slug].get("severity","medium"),9):
            plugins_to_update[slug] = v

    for slug, v in plugins_to_update.items():
        sev      = v.get("severity", "medium")
        fixed_in = v.get("fixed_in", "")
        cve      = v.get("cve_id", "")
        title    = v.get("title", f"Vulnerabilidad en {slug}")
        vtype    = v.get("type", "plugin")

                                   
        priority = 1 if sev == "critical" else (2 if sev == "high" else 3)

        cmds = [
            f"# Actualizar {slug} ({sev.upper()}{' — CVE: '+cve if cve else ''})",
        ]
        if vtype == "theme":
            cmds += [
                wpcli("theme", "update", slug),
                wpcli("theme", "get", slug, "--fields=name,version,status"),
            ]
        else:
            cmds += [
                wpcli("plugin", "update", slug),
                wpcli("plugin", "get", slug, "--fields=name,version,status"),
            ]
            if fixed_in:
                cmds.append(f"# Confirmar versión ≥ {fixed_in}")
                cmds.append(wpcli("plugin", "get", slug, "--field=version"))

                                     
        extra_info = cve_specific.get(cve, {})
        if extra_info.get("extra"):
            cmds += [""] + extra_info["extra"]
            priority = min(priority, extra_info.get("urgency", priority))

        verify = wpcli("plugin", "verify-checksums", slug) if vtype != "theme" else ""

        plan.append(RemediationItem(
            category="vuln",
            priority=priority,
            severity=sev,
            title=title,
            description=f"{'Plugin' if vtype!='theme' else 'Tema'} {slug} v{v.get('plugin_version','?')} → actualizar a ≥{fixed_in or 'última versión'}",
            commands=cmds,
            verify_cmd=verify,
            cve=cve,
            fixed_in=fixed_in,
            plugin_slug=slug,
        ))

                                                                                
    if result.get("xmlrpc_enabled"):
        plan.append(RemediationItem(
            category="config",
            priority=2,
            severity="high",
            title="XML-RPC activo — vector de fuerza bruta y DDoS",
            description=(
                "xmlrpc.php permite ataques de fuerza bruta amplificados (1 petición = "
                "hasta 500 intentos de login). Desactivar si no uses Jetpack o apps móviles."
            ),
            commands=[
                "# Opción 1: via WP-CLI (requiere plugin Disable XML-RPC o función en functions.php)",
                wpcli("option", "get", "xmlrpc_enabled"),
                "# Opción 2: bloquear en .htaccess (Apache)",
                "echo '<Files xmlrpc.php>' >> .htaccess",
                "echo '  Order Deny,Allow' >> .htaccess",
                "echo '  Deny from all' >> .htaccess",
                "echo '</Files>' >> .htaccess",
                "# Opción 3: bloquear en nginx.conf",
                "# location = /xmlrpc.php { deny all; return 403; }",
                "# Verificar que esté bloqueado",
                "curl -s -o /dev/null -w '%{http_code}' " +
                (result.get("target_url","").rstrip("/") + "/xmlrpc.php"),
            ],
            verify_cmd="",
            manual_step="Confirmar que curl devuelve 403 o 404, no 200.",
        ))

                                                                               
    debug = result.get("debug_mode") or {}
    if debug.get("debug_active"):
        plan.append(RemediationItem(
            category="config",
            priority=1,
            severity="high",
            title="WP_DEBUG activo en producción — expone rutas y errores",
            description="WP_DEBUG=true en producción filtra rutas del servidor y stack traces a cualquier visitante.",
            commands=[
                "# Desactivar WP_DEBUG en wp-config.php",
                "sed -i \"s/define('WP_DEBUG', true)/define('WP_DEBUG', false)/\" wp-config.php",
                "sed -i \"s/define('WP_DEBUG_DISPLAY', true)/define('WP_DEBUG_DISPLAY', false)/\" wp-config.php",
                "# Eliminar log de debug si existe",
                "rm -f wp-content/debug.log",
                "# Verificar",
                wpcli("config", "get", "WP_DEBUG"),
            ],
            verify_cmd=wpcli("config", "get", "WP_DEBUG"),
        ))

                                                                                
    users = result.get("users") or []
    if users:
        usernames = [u.get("login") or u.get("display_name","?") for u in users[:5] if isinstance(u, dict)]
        plan.append(RemediationItem(
            category="users",
            priority=2,
            severity="medium",
            title=f"Enumeración de usuarios ({len(users)} detectados sin autenticación)",
            description=(
                f"Usuarios enumerados: {', '.join(usernames)}. "
                "Los usernames facilitan ataques de fuerza bruta."
            ),
            commands=[
                "# Ver todos los usuarios admin",
                wpcli("user", "list", "--role=administrator", "--fields=ID,user_login,user_email"),
                "# Cambiar el display_name para no revelar el login",
                "# wp user update <ID> --display_name='Administrador'",
                "# Proteger enumeración en functions.php",
                "# add_filter('redirect_canonical', fn($r,$q) => is_author() ? false : $r, 10, 2);",
                "# Instalar plugin Stop User Enumeration",
                wpcli("plugin", "install", "stop-user-enumeration", "--activate"),
            ],
            verify_cmd=wpcli("user", "list", "--role=administrator", "--field=user_login"),
        ))

                                                                                
    exposed = result.get("exposed_files") or []
    critical_files = [
        f for f in exposed
        if isinstance(f, dict) and f.get("severity") in ("critical", "high")
    ]
    if critical_files:
        paths = [f.get("path","") for f in critical_files[:6]]
        plan.append(RemediationItem(
            category="files",
            priority=1,
            severity="critical",
            title=f"{len(critical_files)} archivos sensibles accesibles públicamente",
            description=f"Archivos críticos expuestos: {', '.join(paths[:3])}{'...' if len(paths)>3 else ''}",
            commands=[
                "# Eliminar backups de base de datos y archivos sensibles",
                "find . -name '*.sql' -o -name '*.sql.gz' -o -name '*.bak' | head -20",
                "# Eliminar (verificar antes manualmente):",
                "# rm -i $(find . -name '*.sql' -o -name '*.bak' -o -name '*.old')",
                "# Proteger archivos con .htaccess (Apache)",
                "# <FilesMatch '\\.(sql|bak|old|log|gz|zip)$'>",
                "#   Order Deny,Allow",
                "#   Deny from all",
                "# </FilesMatch>",
                "# Verificar que no existen rutas sensibles",
            ] + [f"curl -o /dev/null -w '%{{http_code}} ' {(result.get('target_url','').rstrip('/'))+p}" for p in paths[:3]],
            manual_step="Los códigos 404/403 son correctos. 200 significa que el archivo sigue expuesto.",
        ))

                                                                                
    h_issues = result.get("headers_issues") or []
    if len(h_issues) >= 3:
        plan.append(RemediationItem(
            category="headers",
            priority=3,
            severity="medium",
            title=f"{len(h_issues)} cabeceras de seguridad HTTP ausentes",
            description=f"Faltan: {', '.join(h_issues[:4])}{'...' if len(h_issues)>4 else ''}",
            commands=[
                "# Añadir en functions.php de tu tema hijo:",
                "# add_action('send_headers', function() {",
                "#   header('X-Frame-Options: DENY');",
                "#   header('X-Content-Type-Options: nosniff');",
                "#   header('Referrer-Policy: no-referrer-when-downgrade');",
                "#   header('Permissions-Policy: geolocation=(), microphone=()');",
                "# });",
                "",
                "# O con WP-CLI (instalar plugin HTTP Headers)",
                wpcli("plugin", "install", "http-headers", "--activate"),
                "",
                "# Alternativa: añadir en .htaccess (Apache)",
                "# Header always set X-Frame-Options DENY",
                "# Header always set X-Content-Type-Options nosniff",
                "# Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains'",
            ],
            manual_step="Verificar con: curl -I " + result.get("target_url","https://tu-sitio.com"),
        ))

                                                                               
    ssl = result.get("ssl_info") or {}
    if ssl.get("expired") or (ssl.get("days_left") is not None and ssl["days_left"] < 30):
        days = ssl.get("days_left", 0)
        plan.append(RemediationItem(
            category="ssl",
            priority=1 if ssl.get("expired") else 2,
            severity="critical" if ssl.get("expired") else "high",
            title=f"Certificado SSL {'EXPIRADO' if ssl.get('expired') else f'expira en {days} días'}",
            description=f"Emisor: {ssl.get('issuer','?')}. El certificado {'ya no es válido' if ssl.get('expired') else 'debe renovarse urgentemente'}.",
            commands=[
                "# Renovar con Certbot (Let's Encrypt)",
                "certbot renew --cert-name " + (result.get("target_url","").replace("https://","").replace("http://","").split("/")[0]),
                "# O forzar renovación:",
                "certbot renew --force-renewal",
                "# Verificar fechas del nuevo certificado",
                "echo | openssl s_client -connect " + (result.get("target_url","").replace("https://","").replace("http://","").split("/")[0]) + ":443 2>/dev/null | openssl x509 -noout -dates",
            ],
            manual_step="Reiniciar nginx/Apache tras la renovación: systemctl reload nginx",
        ))

                                                                              
    admin_users = [
        u for u in users
        if isinstance(u, dict) and u.get("login", "").lower() in ("admin", "administrator", "wp-admin", "wordpress")
    ]
    if admin_users:
        plan.append(RemediationItem(
            category="users",
            priority=2,
            severity="high",
            title="Usuario admin con nombre predeterminado detectado",
            description=f"Usuarios: {', '.join(u.get('login','') for u in admin_users)}. Los nombres predeterminados son el primer objetivo en ataques de fuerza bruta.",
            commands=[
                "# Cambiar el login del usuario admin (NO se puede con WP-CLI directamente)",
                "# Método: crear nuevo usuario admin, transferir contenido, eliminar el antiguo",
                wpcli("user", "create", "nuevo-admin", "nuevo-admin@mi-dominio.com", "--role=administrator", "--user_pass=CAMBIA-ESTO"),
                "# Transferir posts del usuario antiguo:",
                wpcli("user", "delete", "admin", "--reassign=<ID-nuevo-usuario>"),
                "# Activar protección de login con límite de intentos",
                wpcli("plugin", "install", "limit-login-attempts-reloaded", "--activate"),
            ],
        ))

                                                                               
    if result.get("login_exposed"):
        plan.append(RemediationItem(
            category="config",
            priority=3,
            severity="low",
            title="Panel de login WordPress accesible públicamente",
            description="/wp-login.php responde 200. Considera mover o proteger el login.",
            commands=[
                "# Instalar plugin para cambiar URL de login",
                wpcli("plugin", "install", "wps-hide-login", "--activate"),
                "# Configurar nueva URL de login (ejemplo: /acceso-seguro)",
                wpcli("option", "update", "whl_page", "acceso-seguro"),
                "# O proteger con HTTP Basic Auth en .htaccess:",
                "# <Files wp-login.php>",
                "#   AuthType Basic",
                "#   AuthName 'Admin'",
                "#   AuthUserFile /ruta-fuera-webroot/.htpasswd",
                "#   Require valid-user",
                "# </Files>",
                "# Generar .htpasswd:",
                "htpasswd -c /etc/nginx/.htpasswd admin",
            ],
        ))

                                                                               
    all_plugins = result.get("plugins") or []
                                                                  
                                                         
    if len(all_plugins) > 10:
        plan.append(RemediationItem(
            category="config",
            priority=3,
            severity="low",
            title=f"Inventario de plugins ({len(all_plugins)} detectados) — revisar inactivos",
            description="Los plugins inactivos siguen siendo un vector de ataque si tienen vulnerabilidades.",
            commands=[
                "# Listar plugins inactivos",
                wpcli("plugin", "list", "--status=inactive", "--fields=name,version,update"),
                "# Eliminar plugins inactivos que no necesites",
                "# wp plugin delete <slug>",
                "# Actualizar TODOS los plugins de una vez",
                wpcli("plugin", "update", "--all"),
                "# Actualizar TODOS los temas",
                wpcli("theme", "update", "--all"),
                "# Ver plugins con actualizaciones disponibles",
                wpcli("plugin", "list", "--update=available", "--fields=name,version,update_version"),
            ],
            verify_cmd=wpcli("plugin", "list", "--update=available"),
        ))

                                                                               
    plan.append(RemediationItem(
        category="hardening",
        priority=3,
        severity="info",
        title="Hardening general recomendado",
        description="Medidas de seguridad adicionales independientes de vulnerabilidades específicas.",
        commands=[
            "# Verificar permisos de ficheros",
            "find . -type f -name '*.php' -perm /o+w | head -20  # PHP escribibles por others",
            "find wp-content/uploads -name '*.php' | head -20     # PHP en uploads (backdoor)",
            "",
            "# Permisos correctos",
            "find . -type d -exec chmod 755 {} \\;",
            "find . -type f -exec chmod 644 {} \\;",
            "chmod 400 wp-config.php",
            "",
            "# Instalar plugin de seguridad completo",
            wpcli("plugin", "install", "wordfence", "--activate"),
            "",
            "# Backup automático",
            wpcli("plugin", "install", "updraftplus", "--activate"),
            "",
            "# Verificar no hay usuarios con contraseñas débiles",
            wpcli("user", "list", "--fields=ID,user_login,user_email,roles"),
            "",
            "# Limpiar caché tras todos los cambios",
            wpcli("cache", "flush"),
            wpcli("rewrite", "flush"),
        ],
    ))

                                    
    plan.sort(key=lambda x: (x.priority, SEV_ORDER.get(x.severity, 9)))
    return plan


                                                                                 
                              
                                                                                 

def run_command(cmd: str, dry_run: bool = True, wp_path: str = "") -> tuple[int, str, str]:
    """Ejecuta un comando WP-CLI y devuelve (returncode, stdout, stderr)."""
    if dry_run:
        return 0, f"[DRY-RUN] {cmd}", ""
                                                            
    if not cmd.startswith("wp "):
        return -1, "", f"Solo se ejecutan comandos 'wp': {cmd[:60]}"
    try:
        result = subprocess.run(
            cmd.split(),
            capture_output=True, text=True, timeout=30,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout (30s)"
    except Exception as e:
        return -1, "", str(e)


                                                                                 
                        
                                                                                 

def export_bash_script(plan: list[RemediationItem], result: dict, output_path: str, wp_path: str = ""):
    """Genera un bash script ejecutable con todos los comandos."""
    lines = [
        "#!/bin/bash",
        "# ═══════════════════════════════════════════════════════════════════",
        "# WP VulnScanner — Script de Remediación",
        f"# Objetivo: {result.get('target_url', '?')}",
        f"# Generado: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"# Risk Score: {result.get('risk_score','?')}/100 ({result.get('risk_label','?')})",
        "# ═══════════════════════════════════════════════════════════════════",
        "",
        "set -euo pipefail",
        "",
    ]

    if wp_path:
        lines += [f'WP_PATH="{wp_path}"', 'cd "$WP_PATH"', ""]
    else:
        lines += [
            '# CONFIGURA LA RUTA A TU INSTALACIÓN WORDPRESS:',
            '# WP_PATH="/var/www/html"',
            '# cd "$WP_PATH"',
            "",
        ]

    lines += [
        'log() { echo "[$(date +%H:%M:%S)] $*"; }',
        'ok()  { echo "✓ $*"; }',
        'err() { echo "✗ $*" >&2; }',
        "",
        "# Verificar WP-CLI disponible",
        "if ! command -v wp &>/dev/null; then",
        "  err 'WP-CLI no encontrado. Instalar: curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && chmod +x wp-cli.phar && mv wp-cli.phar /usr/local/bin/wp'",
        "  exit 1",
        "fi",
        "",
        "log 'Iniciando remediación...'",
        "log 'IMPORTANTE: Hacer backup completo antes de continuar'",
        "wp db export backup-$(date +%Y%m%d-%H%M%S).sql",
        "",
    ]

    for item in plan:
        if item.category == "hardening" and item.priority == 3:
            continue                                                            
        prio_label = PRIORITY_LABEL.get(item.priority, "")
        lines += [
            f"# {'═'*65}",
            f"# {prio_label}: {item.title}",
            f"# {'═'*65}",
            f'log "{item.title}"',
            "",
        ]
        for cmd in item.commands:
            if not cmd.strip():
                lines.append("")
            elif cmd.strip().startswith("#"):
                lines.append(cmd)
            elif cmd.startswith("wp "):
                lines.append(cmd)
            else:
                lines.append(f"# (manual) {cmd}")
        if item.verify_cmd and item.verify_cmd.startswith("wp "):
            lines += ["", "# Verificación:", item.verify_cmd, ""]
        lines.append("")

    lines += [
        "log 'Remediación completada.'",
        "wp cache flush",
        "wp rewrite flush",
        "log 'Caché limpiada. Verificar el sitio manualmente.'",
    ]

    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
    os.chmod(output_path, 0o755)


                                                                                 
                       
                                                                                 

def print_plan(plan: list[RemediationItem], result: dict, verbose: bool = False):
    """Imprime el plan de remediación en terminal con colores."""
    url        = result.get("target_url", "desconocida")
    risk       = result.get("risk_score", 0)
    risk_label = result.get("risk_label", "?")
    scanned_at = result.get("scanned_at", "?")

    print()
    print(_c(C.BOLD, "╔══════════════════════════════════════════════════════════════════╗"))
    print(_c(C.BOLD, "║     WP VulnScanner — Plan de Remediación WP-CLI              ║"))
    print(_c(C.BOLD, "╚══════════════════════════════════════════════════════════════════╝"))
    print()
    info(f"Objetivo:   {_c(C.BLUE, url)}")
    info(f"Escaneado:  {scanned_at}")

    risk_color = C.RED if risk >= 70 else C.ORANGE if risk >= 45 else C.YELLOW if risk >= 20 else C.GREEN
    info(f"Risk Score: {_c(risk_color, f'{risk}/100 ({risk_label})')}")

             
    by_priority = {1: [], 2: [], 3: []}
    for item in plan:
        by_priority[item.priority].append(item)

    print()
    sep()
    print(f"  {_c(C.BOLD, 'RESUMEN')}")
    sep()
    if by_priority[1]:
        print(f"  {_c(C.RED, f'🚨 {len(by_priority[1])} acción(es) INMEDIATA(s)')}")
    if by_priority[2]:
        print(f"  {_c(C.ORANGE, f'⚡ {len(by_priority[2])} acción(es) esta SEMANA')}")
    if by_priority[3]:
        print(f"  {_c(C.YELLOW, f'📅 {len(by_priority[3])} acción(es) este MES')}")
    print()

    current_priority = None
    for idx, item in enumerate(plan, 1):
        if item.priority != current_priority:
            current_priority = item.priority
            color = PRIORITY_COLOR.get(item.priority, C.YELLOW)
            label = PRIORITY_LABEL.get(item.priority, "")
            print()
            sep()
            print(f"  {_c(color, _c(C.BOLD, label))}")
            sep()

        sev_color = {
            "critical": C.RED, "high": C.ORANGE,
            "medium": C.YELLOW, "low": C.GREEN, "info": C.BLUE,
        }.get(item.severity, C.BLUE)

        print()
        print(f"  {_c(C.BOLD, f'[{idx}]')} {_c(sev_color, f'[{item.severity.upper()}]')} {item.title}")
        if item.cve:
            print(f"       CVE: {_c(C.BLUE, item.cve)}")
        print(f"       {_c(C.DIM, item.description)}")
        print()

                  
        for cmd in item.commands:
            if not cmd.strip():
                continue
            if cmd.strip().startswith("#"):
                print(f"       {_c(C.DIM, cmd)}")
            else:
                print(f"       {_c(C.GREEN, '$')} {_c(C.BOLD, cmd)}")

        if item.verify_cmd:
            print()
            print(f"       {_c(C.DIM, '# Verificar:')}")
            print(f"       {_c(C.BLUE, '$')} {_c(C.BOLD, item.verify_cmd)}")

        if item.manual_step:
            print()
            warn(f"Manual: {item.manual_step}")


def print_summary_only(plan: list[RemediationItem], result: dict):
    """Versión corta: solo títulos y prioridades."""
    url   = result.get("target_url","?")
    risk  = result.get("risk_score",0)
    label = result.get("risk_label","?")
    risk_color = C.RED if risk >= 70 else C.ORANGE if risk >= 45 else C.YELLOW if risk >= 20 else C.GREEN

    head(f"Plan de remediación — {url}")
    info(f"Risk Score: {_c(risk_color, f'{risk}/100 ({label})')}")
    print()

    for item in plan:
        color = PRIORITY_COLOR.get(item.priority, C.YELLOW)
        prio  = PRIORITY_LABEL.get(item.priority,"")
        print(f"  {_c(color, prio):<28} {item.title}")
        n_cmds = len([c for c in item.commands if c.strip() and not c.strip().startswith("#")])
        if n_cmds:
            print(f"  {' '*26} {_c(C.DIM, f'→ {n_cmds} comando(s) WP-CLI')}")

    print()
    info("Usa --verbose para ver los comandos completos")
    info("Usa --output script.sh para exportar como script ejecutable")


                                                                                 
      
                                                                                 

def main():
    parser = argparse.ArgumentParser(
        description="WP VulnScanner — Remediación con WP-CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Ejemplos:
          python wp_remediate.py                              # último escaneo
          python wp_remediate.py --url https://mi-wp.com     # URL específica
          python wp_remediate.py --file resultado.json       # desde fichero
          python wp_remediate.py --output fix.sh             # exportar script
          python wp_remediate.py --verbose                   # mostrar comandos
          python wp_remediate.py --priority 1                # solo urgentes
          python wp_remediate.py --category vuln             # solo vulnerabilidades
          python wp_remediate.py --run --wp-path /var/www    # ejecutar WP-CLI
        """)
    )

    parser.add_argument("--url",       help="Filtrar por URL del sitio escaneado")
    parser.add_argument("--file",      help="Fichero JSON exportado de WP VulnScanner")
    parser.add_argument("--output",    help="Exportar plan como bash script (ej: fix.sh)")
    parser.add_argument("--wp-path",   default="", help="Ruta al directorio raíz de WordPress")
    parser.add_argument("--verbose",   action="store_true", help="Mostrar todos los comandos")
    parser.add_argument("--run",       action="store_true", help="Ejecutar comandos WP-CLI directamente")
    parser.add_argument("--dry-run",   action="store_true", default=True, help="No ejecutar (default)")
    parser.add_argument("--priority",  type=int, choices=[1, 2, 3], help="Filtrar por prioridad (1=inmediata)")
    parser.add_argument("--category",  choices=["vuln","config","headers","users","ssl","files","hardening"],
                                       help="Filtrar por categoría")
    parser.add_argument("--summary",   action="store_true", help="Solo mostrar resumen sin comandos")
    parser.add_argument("--no-color",  action="store_true", help="Sin colores de terminal")

    args = parser.parse_args()

    if args.no_color:
                              
        for attr in dir(C):
            if not attr.startswith("_"):
                setattr(C, attr, "")

                                                                                
    if args.file:
        result = load_result_from_file(args.file)
    else:
        result = load_result_from_db(args.url)

    if not result:
        sys.exit(1)

                                                                                
    plan = build_plan(result, wp_path=args.wp_path)

                                                                                
    if args.priority:
        plan = [p for p in plan if p.priority == args.priority]
    if args.category:
        plan = [p for p in plan if p.category == args.category]

    if not plan:
        warn("No se encontraron ítems con los filtros aplicados.")
        sys.exit(0)

                                                                                
    if args.output:
        export_bash_script(plan, result, args.output, wp_path=args.wp_path)
        ok(f"Script exportado: {args.output}")
        ok(f"Ejecutar con: bash {args.output}")
        ok("Revisar el script antes de ejecutarlo en producción.")
        sys.exit(0)

                                                                                
    if args.summary:
        print_summary_only(plan, result)
    else:
        print_plan(plan, result, verbose=args.verbose)

                                                                               
    if args.run:
        head("Ejecutando comandos WP-CLI...")
        dry = not args.run
        executed = 0
        for item in plan:
            if item.priority > 2:
                continue                                                 
            for cmd in item.commands:
                if not cmd.strip() or cmd.strip().startswith("#") or not cmd.startswith("wp "):
                    continue
                print(f"  $ {_c(C.BOLD, cmd)}")
                rc, stdout, stderr = run_command(cmd, dry_run=dry, wp_path=args.wp_path)
                if rc == 0:
                    ok(stdout[:120] if stdout else "OK")
                else:
                    err(stderr[:120] if stderr else f"Error {rc}")
                executed += 1

        info(f"Ejecutados {executed} comandos WP-CLI.")
        if not dry:
            info("Verificar el sitio manualmente tras los cambios.")


if __name__ == "__main__":
    main()

"""
WP VulnScanner — Módulos de detección profunda v5.5
=======================================================
Cobertura máxima de WordPress:
  - REST API deep: rutas, media, settings, application passwords
  - Login security: enumeración username, rate limit, lost password
  - Feed & author enumeration: ?author=N, RSS emails, comment authors
  - WooCommerce: detección + endpoints expuestos (orders, coupons, keys API)
  - Changelog/license: license.txt, CHANGELOG.md, versión exacta
  - Admin-AJAX nopriv: acciones públicas con datos sensibles
  - Pingback SSRF: xmlrpc.php pingback.ping como vector SSRF
  - Application passwords: WP 5.6+ API auth check
  - Staging/dev indicators: subdominios, metaetiquetas, cookies
  - Uploads scanner: archivos peligrosos en /wp-content/uploads/
"""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

log = logging.getLogger("wpvulnscan.deep_scan")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


def _get(session: requests.Session, url: str, timeout: int = 8, **kw) -> Optional[requests.Response]:
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True, **kw)
        return r
    except Exception as e:
        log.debug("deep_scan GET %s: %s", url, e)
        return None


                                                                               
                              
                                                                               

                                                    
REST_SENSITIVE_ROUTES = [
           
    ("/wp-json/wp/v2/users",           "Usuarios enumerables sin auth",                    "high"),
    ("/wp-json/wp/v2/users?per_page=100","Usuarios (paginado) sin auth",                   "high"),
                         
    ("/wp-json/wp/v2/media",           "Attachments/media enumerables sin auth",            "medium"),
    ("/wp-json/wp/v2/media?per_page=100","Galería completa expuesta",                       "medium"),
             
    ("/wp-json/wp/v2/posts",           "Posts públicos via REST (fingerprinting/emails)",   "info"),
    ("/wp-json/wp/v2/pages",           "Páginas via REST (posibles privadas expuestas)",     "medium"),
    ("/wp-json/wp/v2/categories",      "Categorías expuestas",                              "info"),
    ("/wp-json/wp/v2/tags",            "Etiquetas expuestas",                               "info"),
    ("/wp-json/wp/v2/comments",        "Comentarios + emails de autores expuestos",         "medium"),
                                        
    ("/wp-json/wp/v2/settings",        "Ajustes del sitio sin autenticación",               "critical"),
                                 
    ("/wp-json/wp/v2/blocks",          "Bloques reutilizables sin auth",                    "medium"),
    ("/wp-json/wp/v2/block-patterns",  "Patrones de bloque expuestos",                      "info"),
    ("/wp-json/wp/v2/themes",          "Temas activos via REST",                            "low"),
    ("/wp-json/wp/v2/plugins",         "Lista de plugins via REST (admin only?)",           "high"),
             
    ("/wp-json/wp/v2/widgets",         "Widgets sin autenticación",                         "medium"),
    ("/wp-json/wp/v2/sidebars",        "Sidebars expuestos",                                "low"),
                                     
    ("/wp-json/wp/v2/users/me",        "Endpoint de usuario autenticado accesible",         "medium"),
    ("/wp-json/wp/v2/users/1/application-passwords", "Application passwords del admin",     "critical"),
            
    ("/wp-json/wp/v2/search?search=a", "Búsqueda REST (fingerprinting de contenido)",       "low"),
                      
    ("/wp-json/wc/v3/products",        "WooCommerce: productos sin auth",                   "medium"),
    ("/wp-json/wc/v3/orders",          "WooCommerce: pedidos sin auth (crítico)",            "critical"),
    ("/wp-json/wc/v3/customers",       "WooCommerce: clientes sin auth",                    "critical"),
    ("/wp-json/wc/v3/coupons",         "WooCommerce: cupones descuento expuestos",           "high"),
    ("/wp-json/wc/v3/system_status",   "WooCommerce: estado del sistema (info técnica)",    "high"),
                                    
    ("/wp-json/jetpack/v4/settings",   "Jetpack: configuración sin auth",                   "high"),
    ("/wp-json/bbp/v1/forums",         "bbPress: foros sin auth",                           "low"),
    ("/wp-json/buddypress/v1/members", "BuddyPress: miembros sin auth",                     "medium"),
]


def probe_rest_api_routes(
    session: requests.Session,
    base_url: str,
    timeout: int = 8,
) -> dict:
    """
    Enumera y testea rutas REST de WordPress buscando datos expuestos
    sin autenticación. Detecta emails, usuarios, settings y endpoints WooCommerce.
    """
    result: dict = {
        "available": False,
        "exposed_routes": [],
        "emails_found": [],
        "users_via_rest": [],
        "app_passwords_enabled": False,
        "woocommerce_rest": False,
        "all_routes": [],
        "namespace_count": 0,
    }

                                       
    index = _get(session, urljoin(base_url, "/wp-json/"), timeout=timeout)
    if not index or index.status_code != 200:
        return result

    try:
        data = index.json()
    except Exception:
        return result

    result["available"] = True
    namespaces = data.get("namespaces", [])
    result["namespace_count"] = len(namespaces)
    result["all_routes"]      = list(data.get("routes", {}).keys())[:80]

                                              
    if any("wc/" in ns for ns in namespaces):
        result["woocommerce_rest"] = True

                                                 
    if "application-passwords" in str(data):
        result["app_passwords_enabled"] = True

                                           
    def _probe(route_info):
        path, desc, sev = route_info
        url = urljoin(base_url, path)
        r   = _get(session, url, timeout=timeout)
        if not r or r.status_code not in (200, 201):
            return None
        try:
            body = r.json()
        except Exception:
            return None

        finding = {
            "path":    path,
            "desc":    desc,
            "severity": sev,
            "count":   len(body) if isinstance(body, list) else 1,
            "sample":  None,
        }

                                                            
        if isinstance(body, list):
            for item in body[:10]:
                if isinstance(item, dict):
                    email = item.get("email") or item.get("comment_author_email", "")
                    if email and "@" in email:
                        result["emails_found"].append(email)
                    login = (item.get("slug") or item.get("name") or
                             item.get("username") or "")
                    if login and path.endswith("/users"):
                        result["users_via_rest"].append({
                            "login": login,
                            "id":    item.get("id"),
                            "link":  item.get("link", ""),
                        })
            finding["count"] = len(body)
        elif isinstance(body, dict):
                                                              
            if "blogname" in body or "admin_email" in body:
                admin_email = body.get("admin_email", "")
                if admin_email:
                    result["emails_found"].append(admin_email)
                finding["severity"] = "critical"
                finding["sample"]   = f"admin_email={admin_email}"

        return finding

    exposed = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(_probe, ri): ri for ri in REST_SENSITIVE_ROUTES}
        try:
            for fut in as_completed(futs, timeout=min(timeout * 8, 60)):
                res = fut.result()
                if res:
                    exposed.append(res)
        except FuturesTimeout:
            log.warning("⏱️  REST API probe timeout — algunos routes no respondieron a tiempo")

    result["exposed_routes"] = exposed
    result["emails_found"]   = list(set(result["emails_found"]))

    return result


                                                                               
                            
                                                                               

                                           
_TEST_USERS = ["admin", "administrator", "test", "user", "wordpress", "wp-admin"]
_FAKE_USER  = "xzqnobodyxzq9999fakexzq"


def check_login_security(
    session: requests.Session,
    base_url: str,
    timeout: int = 8,
) -> dict:
    """
    Analiza la seguridad de wp-login.php:
    - Enumeración de usuarios vía mensajes de error diferenciados
    - Comprobación de rate limiting / captcha
    - Enumeración vía lost password
    - Application passwords habilitados
    - Login page fingerprintable
    """
    result: dict = {
        "login_accessible":         False,
        "username_enumerable":      False,
        "enum_method":              "",
        "rate_limit_detected":      False,
        "captcha_detected":         False,
        "lost_password_enumerable": False,
        "valid_users_found":        [],
        "login_page_info":          {},
        "issues":                   [],
    }

    login_url = urljoin(base_url, "/wp-login.php")

                                                                              
    r = _get(session, login_url, timeout=timeout)
    if not r or r.status_code != 200 or "log" not in r.text.lower():
        return result

    result["login_accessible"] = True

                      
    if any(sig in r.text.lower() for sig in
           ["recaptcha", "hcaptcha", "cf-turnstile", "captcha", "g-recaptcha"]):
        result["captcha_detected"] = True

                                  
    security_plugins = []
    for sig, name in [
        ("wordfence", "Wordfence"), ("sucuri", "Sucuri"),
        ("ithemes-security", "iThemes Security"), ("loginizer", "Loginizer"),
        ("wps-limit-login", "WPS Limit Login"),
    ]:
        if sig in r.text.lower():
            security_plugins.append(name)
    if security_plugins:
        result["login_page_info"]["security_plugins"] = security_plugins

                                                                               
                                                                  
    def test_user(username: str) -> tuple[str, str]:
        try:
            resp = session.post(
                login_url,
                data={"log": username, "pwd": "WPVS_TEST_INVALID_2024!", "wp-submit": "Log In"},
                timeout=timeout, allow_redirects=True,
            )
            return username, resp.text
        except Exception:
            return username, ""

                                                      
    _, fake_body  = test_user(_FAKE_USER)
    _, admin_body = test_user("admin")

    fake_msg  = ""
    admin_msg = ""

                                 
    for pattern in [
        r'<div id="login_error"[^>]*>(.*?)</div>',
        r'<p class="message"[^>]*>(.*?)</p>',
    ]:
        m = re.search(pattern, fake_body, re.DOTALL | re.IGNORECASE)
        if m:
            fake_msg  = re.sub(r"<[^>]+>", "", m.group(1)).strip()
        m = re.search(pattern, admin_body, re.DOTALL | re.IGNORECASE)
        if m:
            admin_msg = re.sub(r"<[^>]+>", "", m.group(1)).strip()

                                                
    if fake_msg and admin_msg and fake_msg != admin_msg:
        if ("unknown" in fake_msg.lower() or "no account" in fake_msg.lower()
                or "invalid username" in fake_msg.lower()):
            result["username_enumerable"] = True
            result["enum_method"]         = "Mensajes de error diferenciados en wp-login.php"
            result["issues"].append(
                "Username enumeration: wp-login.php diferencia 'usuario inexistente' "
                "de 'contraseña incorrecta'"
            )

                                                                              
    lp_url = urljoin(base_url, "/wp-login.php?action=lostpassword")
    try:
        r_lp = session.get(lp_url, timeout=timeout)
        if r_lp.status_code == 200 and "lost" in r_lp.text.lower():
                                  
            resp_lp = session.post(
                lp_url,
                data={"user_login": _FAKE_USER, "wp-submit": "Get New Password"},
                timeout=timeout, allow_redirects=True,
            )
            lp_text = resp_lp.text.lower()
            if any(sig in lp_text for sig in [
                "no account found", "there is no account",
                "invalid username", "no hay ninguna cuenta"
            ]):
                result["lost_password_enumerable"] = True
                result["issues"].append(
                    "Username enumeration vía lost password: respuesta diferente para "
                    "usuario existente vs inexistente"
                )
    except Exception as _e:
        log.debug("non-critical path suppressed: %s", _e)

                                                                              
                                                                               
    if not result["captcha_detected"]:
        blocked = False
        for _ in range(5):
            try:
                r_rl = session.post(
                    login_url,
                    data={"log": "admin", "pwd": f"test{_}invalid!", "wp-submit": "Log In"},
                    timeout=timeout,
                )
                if r_rl.status_code in (429, 503):
                    blocked = True
                    break
                if "too many" in r_rl.text.lower() or "lockout" in r_rl.text.lower():
                    blocked = True
                    break
            except Exception:
                break

        result["rate_limit_detected"] = blocked
        if not blocked:
            result["issues"].append(
                "Sin rate limiting en wp-login.php — fuerza bruta sin obstáculos detectados"
            )

    return result


                                                                               
                              
                                                                               

def check_feed_author_enumeration(
    session: requests.Session,
    base_url: str,
    timeout: int = 8,
) -> dict:
    """
    Enumera usuarios y emails mediante:
    - ?author=N redirect (IDs 1-10)
    - RSS feeds (autor + email en <author>)
    - Sitemap de autores
    - Comment RSS feed
    """
    result: dict = {
        "authors_via_redirect":   [],
        "authors_via_feed":       [],
        "emails_in_feeds":        [],
        "comment_authors":        [],
        "author_enum_possible":   False,
        "issues":                 [],
    }

                                                                               
    for uid in range(1, 11):
        try:
            r = session.get(
                urljoin(base_url, f"/?author={uid}"),
                timeout=timeout, allow_redirects=False,
            )
            if r.status_code in (301, 302):
                loc = r.headers.get("Location", "")
                                           
                m = re.search(r"/author/([^/?\s]+)", loc)
                if m:
                    slug = m.group(1)
                    if slug and slug not in result["authors_via_redirect"]:
                        result["authors_via_redirect"].append(slug)
                        result["author_enum_possible"] = True
            elif r.status_code == 200:
                                                                               
                m = re.search(r'class="author[^"]*"[^>]*>([^<]{2,40})<', r.text)
                if m:
                    result["authors_via_redirect"].append(m.group(1).strip())
                    result["author_enum_possible"] = True
        except Exception as _e:
            log.debug("non-critical path suppressed: %s", _e)

    if result["author_enum_possible"]:
        result["issues"].append(
            f"Enumeración de usuarios via ?author=N: "
            f"{len(result['authors_via_redirect'])} usuario(s) revelado(s)"
        )

                                                                               
    for feed_path in ["/?feed=rss2", "/?feed=rss", "/?feed=atom", "/feed/"]:
        r = _get(session, urljoin(base_url, feed_path), timeout=timeout)
        if not r or r.status_code != 200:
            continue
        text = r.text

                                  
        for pat in [
            r"<dc:creator><!\[CDATA\[([^\]]+)\]\]>",
            r"<author><name>([^<]{2,60})</name>",
            r"<author>([^<@\s]{2,40})</author>",
        ]:
            for m in re.finditer(pat, text):
                name = m.group(1).strip()
                if name and name not in result["authors_via_feed"]:
                    result["authors_via_feed"].append(name)

                                                     
        for m in re.finditer(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", text):
            email = m.group(0).lower()
            if email not in result["emails_in_feeds"]:
                result["emails_in_feeds"].append(email)

        break                                

                                                                               
    r_com = _get(session, urljoin(base_url, "/?feed=comments-rss2"), timeout=timeout)
    if r_com and r_com.status_code == 200:
        for pat in [
            r"<dc:creator><!\[CDATA\[([^\]]+)\]\]>",
            r"<author>([^<@\s]{2,40})</author>",
        ]:
            for m in re.finditer(pat, r_com.text):
                name = m.group(1).strip()
                if name and name not in result["comment_authors"]:
                    result["comment_authors"].append(name)

    if result["emails_in_feeds"]:
        result["issues"].append(
            f"Emails expuestos en feed RSS: {', '.join(result['emails_in_feeds'][:3])}"
        )

    return result


                                                                               
                         
                                                                               

WOOCOMMERCE_SIGNALS = [
    ("woocommerce",          "/wp-content/plugins/woocommerce/"),
    ("wc-ajax",              "wc-ajax="),
    ("woocommerce-cart",     "woocommerce-cart"),
    ("wc_session",           "wc_session"),
    ("WooCommerce",          "WooCommerce"),
    ("add-to-cart",          "add-to-cart"),
]

WOOCOMMERCE_EXPOSED_PATHS = [
    ("/shop/",                          "Tienda WooCommerce accesible",                 "info"),
    ("/cart/",                          "Carrito accesible",                            "info"),
    ("/checkout/",                      "Checkout accesible",                           "info"),
    ("/my-account/",                    "Mi cuenta WooCommerce accesible",              "info"),
    ("/wp-json/wc/v3/products",         "API WC: productos sin auth",                   "medium"),
    ("/wp-json/wc/v3/orders",           "API WC: pedidos sin auth (CRÍTICO)",            "critical"),
    ("/wp-json/wc/v3/customers",        "API WC: clientes sin auth",                    "critical"),
    ("/wp-json/wc/v3/coupons",          "API WC: cupones descuento expuestos",           "high"),
    ("/wp-json/wc/v3/reports/sales",    "API WC: informe de ventas sin auth",            "critical"),
    ("/wp-json/wc/v3/system_status",    "API WC: estado del sistema (info técnica)",    "high"),
    ("/wp-json/wc/v3/payment_gateways", "API WC: métodos de pago expuestos",            "high"),
    ("/?wc-api=wc_payment_checkout",    "WC Payment webhook accesible",                 "medium"),
    ("/wc-auth/v1/authorize",           "WC OAuth endpoint expuesto",                   "high"),
    ("/wp-content/plugins/woocommerce/includes/","Directory listing en WooCommerce core","medium"),
]


def detect_woocommerce(
    session: requests.Session,
    base_url: str,
    html: str = "",
    timeout: int = 8,
) -> dict:
    """Detecta WooCommerce y verifica exposición de endpoints sensibles."""
    result: dict = {
        "detected":        False,
        "version":         None,
        "exposed_paths":   [],
        "api_accessible":  False,
        "issues":          [],
    }

                                  
    if html:
        for _, signal in WOOCOMMERCE_SIGNALS:
            if signal in html:
                result["detected"] = True
                break

                            
    if not result["detected"]:
        r = _get(session, urljoin(base_url, "/wp-content/plugins/woocommerce/woocommerce.php"),
                 timeout=timeout)
        if r and r.status_code == 200 and "woocommerce" in r.text.lower():
            result["detected"] = True

    if not result["detected"]:
        return result

                         
    r_ver = _get(session, urljoin(base_url, "/wp-content/plugins/woocommerce/readme.txt"),
                 timeout=timeout)
    if r_ver and r_ver.status_code == 200:
        m = re.search(r"Stable tag:\s*([\d.]+)", r_ver.text, re.IGNORECASE)
        if m:
            result["version"] = m.group(1)

                               
    def _probe_wc(info):
        path, desc, sev = info
        url = urljoin(base_url, path)
        r   = _get(session, url, timeout=timeout)
        if not r or r.status_code not in (200, 201):
            return None
                                                              
        if "/wp-json/wc/" in path:
            try:
                body = r.json()
                if isinstance(body, list) and len(body) > 0:
                    result["api_accessible"] = True
                    return {"path": path, "desc": desc, "severity": sev,
                            "count": len(body)}
                elif isinstance(body, dict) and not body.get("code"):
                    result["api_accessible"] = True
                    return {"path": path, "desc": desc, "severity": sev,
                            "count": 1}
            except Exception as _e:
                log.debug("non-critical path suppressed: %s", _e)
            return None
        return {"path": path, "desc": desc, "severity": sev, "count": 1}

    exposed = []
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = [ex.submit(_probe_wc, info) for info in WOOCOMMERCE_EXPOSED_PATHS]
        for f in as_completed(futs, timeout=40):
            res = f.result()
            if res:
                exposed.append(res)

    result["exposed_paths"] = exposed
    if any(p["severity"] in ("critical", "high") for p in exposed):
        result["issues"].append(
            "WooCommerce: endpoints críticos accesibles sin autenticación"
        )

    return result


                                                                               
                                          
                                                                               

CHANGELOG_PATHS = [
                    
    ("/license.txt",                        "Versión de WordPress en license.txt",               "medium"),
    ("/licencia.txt",                       "Versión en licencia.txt (ES)",                      "medium"),
    ("/wp-admin/about.php",                 "Página About WP (versión exacta)",                  "medium"),
                       
    ("/wp-content/plugins/akismet/readme.txt",    "Versión de Akismet expuesta",                 "low"),
    ("/wp-content/plugins/woocommerce/readme.txt","Versión de WooCommerce expuesta",             "low"),
    ("/wp-content/plugins/contact-form-7/readme.txt","Versión CF7 expuesta",                     "low"),
    ("/wp-content/plugins/yoast-seo/readme.txt",  "Versión Yoast SEO expuesta",                  "low"),
    ("/wp-content/plugins/elementor/readme.txt",  "Versión Elementor expuesta",                  "low"),
                      
    ("/CHANGELOG.md",                       "CHANGELOG.md expuesto en raíz",                     "medium"),
    ("/CHANGELOG.txt",                      "CHANGELOG.txt expuesto en raíz",                    "medium"),
    ("/changelog.md",                       "changelog.md expuesto en raíz",                     "medium"),
    ("/CHANGES.md",                         "CHANGES.md expuesto",                               "medium"),
    ("/CHANGES.txt",                        "CHANGES.txt expuesto",                              "medium"),
    ("/VERSION",                            "Archivo VERSION expuesto",                          "medium"),
    ("/version.txt",                        "version.txt expuesto",                              "medium"),
    ("/wp-content/upgrade/",               "Directorio upgrade accesible",                       "medium"),
    ("/wp-content/uploads/changelog.txt",  "Changelog en uploads",                               "medium"),
                           
    ("/wp-content/plugins/debug.log",      "Log de debug en plugins",                            "high"),
    ("/wp-content/themes/debug.log",       "Log de debug en themes",                             "high"),
    ("/npm-debug.log",                     "Log de npm expuesto",                                "high"),
    ("/yarn-error.log",                    "Log de yarn expuesto",                               "high"),
    ("/.npmrc",                            "Configuración npm (posibles tokens)",                 "high"),
    ("/.yarnrc",                           "Configuración yarn expuesta",                        "medium"),
    ("/Makefile",                          "Makefile expuesto (info de build)",                  "medium"),
    ("/Gruntfile.js",                      "Gruntfile.js expuesto",                              "low"),
    ("/Gruntfile.coffee",                  "Gruntfile.coffee expuesto",                          "low"),
    ("/gulpfile.js",                       "Gulpfile.js expuesto",                               "low"),
    ("/webpack.config.js",                 "webpack.config.js expuesto",                         "medium"),
    ("/.babelrc",                          ".babelrc expuesto (config de transpilación)",        "low"),
    ("/.travis.yml",                       ".travis.yml expuesto (CI/CD config)",                "medium"),
    ("/.circleci/config.yml",              "CircleCI config expuesto",                           "medium"),
    ("/.github/workflows/",               "GitHub Actions workflows expuestos",                  "medium"),
    ("/Dockerfile",                        "Dockerfile expuesto (arquitectura interna)",          "high"),
    ("/docker-compose.yml",                "docker-compose.yml expuesto",                        "high"),
    ("/docker-compose.yaml",               "docker-compose.yaml expuesto",                       "high"),
]


def scan_changelog_version_files(
    session: requests.Session,
    base_url: str,
    timeout: int = 8,
) -> dict:
    """
    Escanea archivos de changelog, licencia, versión y artefactos de desarrollo
    que revelan información de versiones e infraestructura.
    """
    result: dict = {
        "found":        [],
        "versions":     {},
        "issues":       [],
    }

    def _probe(info):
        path, desc, sev = info
        url = urljoin(base_url, path)
        r   = _get(session, url, timeout=timeout)
        if not r or r.status_code != 200:
            return None
        text = r.text.strip()
        if not text or len(text) < 10:
            return None
                                       
        if any(sig in text[:200].lower() for sig in
               ["404", "not found", "page not found", "no encontrada"]):
            return None

        version_found = None

                                                     
        if "license.txt" in path:
            m = re.search(r"WordPress(?:[^\n]*?)?(?:- Version|Version)\s+([\d.]+)", text, re.IGNORECASE)
            if not m:
                m = re.search(r"Version ([\d.]+)", text[:500])
            if m:
                version_found = m.group(1)

                                                 
        if "readme.txt" in path and "Stable tag" in text:
            m = re.search(r"Stable tag:\s*([\d.a-z.-]+)", text, re.IGNORECASE)
            if m:
                slug = path.split("/plugins/")[-1].split("/")[0] if "/plugins/" in path else "unknown"
                version_found = m.group(1)
                result["versions"][slug] = version_found

        return {
            "path":    path,
            "url":     url,
            "desc":    desc,
            "severity": sev,
            "version": version_found,
            "size":    len(text),
        }

    found = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(_probe, info) for info in CHANGELOG_PATHS]
        try:
            for f in as_completed(futs, timeout=min(timeout * 10, 80)):
                res = f.result()
                if res:
                    found.append(res)
        except FuturesTimeout:
            log.warning("⏱️  Version file check timeout — algunos archivos no pudieron verificarse")

    result["found"] = found
    if found:
        result["issues"].append(
            f"{len(found)} archivo(s) de changelog/versión expuesto(s)"
        )

    return result


                                                                               
                              
                                                                               

                                                         
                                                  
NOPRIV_AJAX_ACTIONS = [
    ("heartbeat",                "WP Heartbeat API — abusable para DoS CPU",               "medium"),
    ("wc_get_variation",         "WC: variaciones de producto sin auth",                   "low"),
    ("woocommerce_get_refreshed_fragments", "WC: fragmentos carrito sin auth",             "low"),
    ("send-password-reset",      "Reseteo de contraseña sin auth via AJAX",                "medium"),
    ("ajax_login",               "Login via AJAX (algunos plugins)",                       "medium"),
    ("divi_facebook_sdk",        "Divi: SDK Facebook sin auth",                            "low"),
    ("the_champ_user_like",      "Plugin likes: acción sin auth",                          "low"),
    ("generatepress_menu",       "GeneratePress: menú via AJAX sin auth",                  "low"),
    ("avada_recaptcha_verify",   "Avada: verificación recaptcha sin auth",                  "low"),
    ("vc_get_autocomplete_suggestion","Visual Composer: autocompletar sin auth",            "medium"),
    ("mce_view_ajax",            "TinyMCE view ajax sin auth",                             "low"),
    ("save_user_meta_ajax",      "Save user meta sin auth (posible escalada)",              "high"),
    ("download_backup",          "Download backup sin auth (crítico)",                      "critical"),
    ("ajax_verify_order",        "Verificación de pedido sin auth",                         "high"),
    ("af_get_paged_posts",       "Advanced Filters: posts paginados sin auth",              "low"),
    ("get_comments",             "Comentarios via AJAX sin auth",                          "low"),
    ("wp_ajax_nopriv_get_posts", "Posts via AJAX sin auth (info leakage)",                  "low"),
    ("elementor_ajax",           "Elementor AJAX (puede exponer datos)",                   "medium"),
    ("fusion_get_post",          "Fusion Builder: post sin auth",                          "low"),
]


def probe_admin_ajax_actions(
    session: requests.Session,
    base_url: str,
    timeout: int = 8,
) -> dict:
    """
    Prueba acciones wp-admin/admin-ajax.php que no requieren autenticación
    buscando respuestas que indiquen exposición de datos o abuso potencial.
    """
    result: dict = {
        "ajax_accessible":  False,
        "exposed_actions":  [],
        "issues":           [],
    }

    ajax_url = urljoin(base_url, "/wp-admin/admin-ajax.php")

                                           
    r = _get(session, ajax_url, timeout=timeout)
    if not r:
        return result

                                                       
    if r.status_code == 200:
        result["ajax_accessible"] = True

    def _probe_action(info):
        action, desc, sev = info
        try:
            resp = session.post(
                ajax_url,
                data={"action": action},
                timeout=timeout,
            )
            if resp.status_code == 200:
                body = resp.text.strip()
                                                       
                if body in ("", "0", "-1", "false", "null", "[]", "{}", "{}"):
                    return None
                                                  
                is_interesting = (
                    len(body) > 20 and
                    body not in ("0", "-1") and
                    "You are not allowed" not in body and
                    "insufficient" not in body.lower()
                )
                if is_interesting:
                    return {
                        "action":  action,
                        "desc":    desc,
                        "severity": sev,
                        "response_size": len(body),
                        "preview": body[:100],
                    }
        except Exception as _e:
            log.debug("non-critical path suppressed: %s", _e)
        return None

    found = []
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = [ex.submit(_probe_action, info) for info in NOPRIV_AJAX_ACTIONS]
        try:
            for f in as_completed(futs, timeout=min(timeout * 6, 50)):
                res = f.result()
                if res:
                    found.append(res)
        except FuturesTimeout:
            log.warning("⏱️  Admin-ajax check timeout — algunas acciones no pudieron verificarse")

    result["exposed_actions"] = found
    if found:
        result["issues"].append(
            f"{len(found)} acción(es) admin-ajax.php sin auth con respuesta"
        )

    return result


                                                                               
                  
                                                                               

def check_pingback_ssrf(
    session: requests.Session,
    base_url: str,
    timeout: int = 8,
) -> dict:
    """
    Verifica si XML-RPC está activo y si puede ser usado como vector SSRF
    mediante pingback.ping. No realiza el ataque real; solo verifica si
    la condición estructural está presente.
    """
    result: dict = {
        "xmlrpc_accessible": False,
        "pingback_enabled":  False,
        "ssrf_risk":         False,
        "methods":           [],
        "issues":            [],
    }

    xmlrpc_url = urljoin(base_url, "/xmlrpc.php")

                         
    r = _get(session, xmlrpc_url, timeout=timeout)
    if not r or r.status_code != 405:
                                                                                             
        if r and r.status_code == 200 and "xml-rpc" in r.text.lower():
            result["xmlrpc_accessible"] = True
        elif r and r.status_code == 405:
            result["xmlrpc_accessible"] = True
    else:
        result["xmlrpc_accessible"] = True

    if not result["xmlrpc_accessible"]:
        return result

                                
    try:
        list_methods_payload = (
            "<?xml version='1.0'?>"
            "<methodCall><methodName>system.listMethods</methodName>"
            "<params/></methodCall>"
        )
        resp = session.post(
            xmlrpc_url,
            data=list_methods_payload,
            headers={"Content-Type": "text/xml"},
            timeout=timeout,
        )
        if resp.status_code == 200 and "<value>" in resp.text:
            methods = re.findall(r"<value><string>([^<]+)</string></value>", resp.text)
            result["methods"] = methods[:30]
            if "pingback.ping" in methods:
                result["pingback_enabled"] = True
                result["ssrf_risk"]        = True
                result["issues"].append(
                    "pingback.ping disponible en XML-RPC — vector SSRF/amplificación DDoS activo"
                )
            if "wp.getUsersBlogs" in methods:
                result["issues"].append(
                    "wp.getUsersBlogs disponible — XML-RPC fuerza bruta de credenciales posible"
                )
            if "system.multicall" in methods:
                result["issues"].append(
                    "system.multicall disponible — ataques de fuerza bruta amplificados (N×) posibles"
                )
    except Exception as e:
        log.debug("pingback check: %s", e)

    return result


                                                                               
                                    
                                                                               

def check_application_passwords(
    session: requests.Session,
    base_url: str,
    timeout: int = 8,
) -> dict:
    """
    Verifica si Application Passwords (WP 5.6+) está habilitado y si
    la autenticación básica sobre la REST API es posible.
    Esto permite acceso programático a la API con usuario:app-password.
    """
    result: dict = {
        "feature_enabled":     False,
        "basic_auth_accepted": False,
        "endpoint_accessible": False,
        "issues":              [],
    }

                                                      
    for uid in [1, "me"]:
        url = urljoin(base_url, f"/wp-json/wp/v2/users/{uid}/application-passwords")
        r   = _get(session, url, timeout=timeout)
        if r and r.status_code in (200, 401, 403):
            result["endpoint_accessible"] = True
            if r.status_code == 401:
                result["feature_enabled"] = True
                result["issues"].append(
                    "Application Passwords habilitado (WP 5.6+) — "
                    "permite acceso API con user:app-password via HTTP Basic Auth"
                )
            elif r.status_code == 200:
                result["feature_enabled"]     = True
                result["basic_auth_accepted"] = True
                result["issues"].append(
                    "Application Passwords sin restricción — "
                    "endpoint accesible sin autenticación"
                )
            break

                                                                                               
    if not result["feature_enabled"]:
        try:
            r2 = session.get(
                urljoin(base_url, "/wp-json/wp/v2/users/me"),
                auth=("admin", "invalid_password_test"),
                timeout=timeout,
            )
            if r2.status_code == 403 and "incorrect_password" in r2.text:
                result["feature_enabled"] = True
                result["issues"].append(
                    "HTTP Basic Auth aceptado en REST API (Application Passwords activo)"
                )
        except Exception as _e:
            log.debug("non-critical path suppressed: %s", _e)

    return result


                                                                               
                                     
                                                                               

STAGING_META_SIGNALS = [
    ("robots", "noindex"),
    ("robots", "none"),
    ("x-robots-tag", "noindex"),
    ("x-robots-tag", "none"),
]

STAGING_COOKIE_SIGNALS = [
    "staging", "preview", "sandbox", "test", "dev", "stg",
    "wpstg", "wpe-auth", "noindex",
]

STAGING_HEADER_SIGNALS = {
    "X-Staging":        "Cabecera X-Staging presente (entorno staging)",
    "X-WP-Nonce-Stage": "Entorno staging WP detectado via cabecera",
    "Pantheon-SKey":    "Hosting Pantheon (staging puede estar expuesto)",
    "X-Kinsta-Cache":   "Hosting Kinsta detectado",
    "X-WPE-Request-ID": "WP Engine detectado",
    "X-LiteSpeed-Cache":"LiteSpeed Cache detectado",
    "X-Varnish":        "Varnish cache activo (info de infraestructura)",
    "X-Cache":          "Caché de proxy detectado",
    "CF-Ray":           "Cloudflare activo",
    "X-Sucuri-ID":      "Sucuri WAF activo",
}

def detect_staging_environment(
    session: requests.Session,
    base_url: str,
    html: str = "",
    headers: dict = None,
    timeout: int = 8,
) -> dict:
    """
    Detecta indicadores de entorno staging/desarrollo:
    - Meta robots noindex (posible entorno no-prod indexado accidentalmente)
    - Cookies de staging
    - Cabeceras de hosting específicas
    - URLs que contienen staging/dev/test
    - WP_DEBUG activo (ya detectado en otro módulo pero ampliado)
    """
    result: dict = {
        "is_staging":       False,
        "staging_signals":  [],
        "hosting_platform": None,
        "cdn_detected":     None,
        "issues":           [],
    }

    hdrs = headers or {}

                                                                                
    parsed = urlparse(base_url)
    host   = parsed.hostname or ""
    for sig in ["staging", "stage", ".dev.", "dev.", "test.", "sandbox",
                "preview", "uat.", ".local", "stg."]:
        if sig in host:
            result["is_staging"] = True
            result["staging_signals"].append(f"Hostname indica entorno staging: {host}")
            break

                                                                                
    if html:
        if re.search(r'<meta[^>]+name=["\']robots["\'][^>]+content=["\'][^"\']*noindex',
                     html, re.IGNORECASE):
            result["staging_signals"].append(
                "Meta robots noindex detectado — posible entorno de desarrollo expuesto")

                                  
        if "WordPress database error" in html or "PHP Fatal" in html or "PHP Warning" in html:
            result["staging_signals"].append("Errores PHP/WordPress visibles en HTML (WP_DEBUG activo)")
            result["is_staging"] = True

                                                                                
    for header, desc in STAGING_HEADER_SIGNALS.items():
        val = hdrs.get(header) or hdrs.get(header.lower(), "")
        if val:
            if header in ("CF-Ray",):
                result["cdn_detected"] = "Cloudflare"
            elif header in ("X-Kinsta-Cache",):
                result["hosting_platform"] = "Kinsta"
            elif header in ("X-WPE-Request-ID",):
                result["hosting_platform"] = "WP Engine"
            elif header in ("X-Sucuri-ID",):
                result["hosting_platform"] = "Sucuri"
            else:
                result["staging_signals"].append(f"{desc} ({header}: {str(val)[:40]})")

                                                                                
    r = _get(session, base_url, timeout=timeout)
    if r:
        cookies_str = str(r.cookies).lower()
        for sig in STAGING_COOKIE_SIGNALS:
            if sig in cookies_str:
                result["is_staging"] = True
                result["staging_signals"].append(f"Cookie de staging detectada: '{sig}'")
                break

    if result["is_staging"] and result["staging_signals"]:
        result["issues"].append(
            "Entorno de staging/desarrollo accesible públicamente"
        )

    return result


                                                                               
                                                                   
                                                                               

                                                                            
DANGEROUS_UPLOAD_PATTERNS = [
                            
    ("/wp-content/uploads/shell.php",          "PHP shell en uploads",                       "critical"),
    ("/wp-content/uploads/c99.php",            "c99 webshell en uploads",                    "critical"),
    ("/wp-content/uploads/r57.php",            "r57 webshell en uploads",                    "critical"),
    ("/wp-content/uploads/b374k.php",          "b374k webshell en uploads",                  "critical"),
    ("/wp-content/uploads/wso.php",            "WSO webshell en uploads",                    "critical"),
    ("/wp-content/uploads/bypass.php",         "PHP bypass script en uploads",               "critical"),
    ("/wp-content/uploads/cmd.php",            "PHP cmd shell en uploads",                   "critical"),
    ("/wp-content/uploads/eval.php",           "PHP eval script en uploads",                 "critical"),
    ("/wp-content/uploads/upload.php",         "PHP upload handler en uploads",              "critical"),
    ("/wp-content/uploads/backdoor.php",       "PHP backdoor en uploads",                    "critical"),
               
    ("/wp-content/uploads/database.sql",       "Dump SQL en uploads",                        "critical"),
    ("/wp-content/uploads/dump.sql",           "Dump SQL en uploads",                        "critical"),
    ("/wp-content/uploads/backup.sql",         "Backup SQL en uploads",                      "critical"),
    ("/wp-content/uploads/wp_backup.sql",      "Backup WP SQL en uploads",                   "critical"),
    ("/wp-content/uploads/wordpress.sql",      "Dump WordPress SQL en uploads",              "critical"),
    ("/wp-content/uploads/db_backup.sql",      "Backup de base de datos en uploads",         "critical"),
                                               
    ("/wp-content/uploads/backup.zip",         "Backup ZIP en uploads",                      "high"),
    ("/wp-content/uploads/backup.tar.gz",      "Backup tar.gz en uploads",                   "high"),
    ("/wp-content/uploads/site.zip",           "ZIP del sitio en uploads",                   "high"),
    ("/wp-content/uploads/wordpress.zip",      "WordPress ZIP en uploads",                   "high"),
    ("/wp-content/uploads/wp-backup.zip",      "Backup WP ZIP en uploads",                   "high"),
    ("/wp-content/uploads/files.zip",          "ZIP de archivos en uploads",                 "high"),
                  
    ("/wp-content/uploads/wp-config.php",      "wp-config.php en uploads (crítico)",         "critical"),
    ("/wp-content/uploads/.env",               ".env en uploads",                            "critical"),
    ("/wp-content/uploads/config.php",         "config.php en uploads",                      "critical"),
               
    ("/wp-content/uploads/access.log",         "Access log en uploads",                      "high"),
    ("/wp-content/uploads/error.log",          "Error log en uploads",                       "high"),
    ("/wp-content/uploads/php_error.log",      "PHP error log en uploads",                   "high"),
                                                  
    ("/wp-content/uploads/users.csv",          "CSV de usuarios en uploads",                 "high"),
    ("/wp-content/uploads/customers.csv",      "CSV de clientes en uploads",                 "critical"),
    ("/wp-content/uploads/orders.csv",         "CSV de pedidos en uploads",                  "critical"),
    ("/wp-content/uploads/emails.csv",         "CSV de emails en uploads",                   "high"),
    ("/wp-content/uploads/export.csv",         "Export CSV en uploads",                      "medium"),
                        
    ("/wp-content/uploads/cron.php",           "Script cron en uploads",                     "high"),
    ("/wp-content/uploads/wp-cron.php",        "WP-Cron en uploads",                         "high"),
                       
    ("/wp-content/uploads/update.js",          "JS sospechoso en uploads",                   "medium"),
    ("/wp-content/uploads/jquery.js",          "Posible jQuery malicioso en uploads",        "medium"),
]


def scan_uploads_dangerous_files(
    session: requests.Session,
    base_url: str,
    timeout: int = 8,
) -> dict:
    """
    Escanea el directorio de uploads en busca de archivos peligrosos:
    webshells PHP, dumps SQL, backups, configs y datos sensibles.
    """
    result: dict = {
        "directory_listing":  False,
        "dangerous_files":    [],
        "issues":             [],
    }

                                            
    r = _get(session, urljoin(base_url, "/wp-content/uploads/"), timeout=timeout)
    if r and r.status_code == 200:
        if any(sig in r.text for sig in ["Index of /", "Parent Directory", "Directory listing"]):
            result["directory_listing"] = True
            result["issues"].append(
                "Directory listing activo en /wp-content/uploads/ — "
                "todos los archivos son enumerables"
            )

                                            
    def _probe(info):
        path, desc, sev = info
        url = urljoin(base_url, path)
        r   = _get(session, url, timeout=timeout)
        if not r or r.status_code != 200:
            return None
        text = r.text.strip()
        if not text or len(text) < 5:
            return None
        if any(sig in text[:100].lower() for sig in ["404", "not found"]):
            return None

                                                                         
        if path.endswith(".php"):
                                                                     
            is_shell = any(sig in text for sig in [
                "<?php", "eval(", "base64_decode(", "shell_exec(",
                "system(", "passthru(", "phpinfo()", "uid=",
            ])
            if not is_shell and len(text) < 100:
                return None

        return {
            "path":    path,
            "url":     url,
            "desc":    desc,
            "severity": sev,
            "size":    len(text),
        }

    found = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(_probe, info) for info in DANGEROUS_UPLOAD_PATTERNS]
        try:
            for f in as_completed(futs, timeout=min(timeout * 8, 60)):
                res = f.result()
                if res:
                    found.append(res)
        except FuturesTimeout:
            log.warning("⏱️  Dangerous file check timeout — algunos patrones en uploads/ no pudieron verificarse")

    result["dangerous_files"] = found
    if found:
        crits = [f for f in found if f["severity"] == "critical"]
        if crits:
            result["issues"].append(
                f"{len(crits)} archivo(s) crítico(s) en uploads/ (posibles webshells/dumps)"
            )
        else:
            result["issues"].append(
                f"{len(found)} archivo(s) peligroso(s) en uploads/"
            )

    return result


                                                                               
                                                            
                                                                               

def run_deep_scan(
    session: requests.Session,
    base_url: str,
    html: str = "",
    headers: dict = None,
    timeout: int = 8,
    progress_callback=None,
    is_wordpress: bool = True,
) -> dict:
    """
    Ejecuta todos los módulos de deep scan de WordPress en paralelo.
    Si is_wordpress=False, solo ejecuta módulos genéricos (staging, changelog).
    Retorna un dict con los resultados de cada módulo.
    """
                                
    try:
        return _run_deep_scan_impl(session, base_url, html, headers, timeout, progress_callback, is_wordpress)
    except Exception as _ds_err:
        log.error("run_deep_scan error inesperado: %s", _ds_err, exc_info=True)
        return {"error": str(_ds_err), "rest_deep": {}, "login_security": {},
                "changelog": {}, "staging": {}, "feed_enum": {}, "woocommerce": {},
                "app_passwords": {}, "pingback": {}, "ajax_nopriv": {}, "uploads": {}}


def _run_deep_scan_impl(
    session: requests.Session,
    base_url: str,
    html: str = "",
    headers: dict = None,
    timeout: int = 8,
    progress_callback=None,
    is_wordpress: bool = True,
) -> dict:
    def cb(msg, pct):
        if progress_callback:
            progress_callback(msg, pct)

    results: dict = {}

    if not is_wordpress:
        cb("Staging environment detection...", 50)
        try:
            results["staging"] = detect_staging_environment(
                session, base_url, html, headers, timeout)
        except Exception as e:
            log.warning("staging: %s", e)
            results["staging"] = {"error": str(e)}

        cb("Changelog / version files...", 80)
        try:
            results["changelog"] = scan_changelog_version_files(session, base_url, timeout)
        except Exception as e:
            log.warning("changelog: %s", e)
            results["changelog"] = {"error": str(e)}

        cb("Deep scan completado (non-WP).", 100)
        return results

                                                            
    DEEP_TIMEOUT = 120                                    

    modules = {
        "rest_deep":     lambda: probe_rest_api_routes(session, base_url, timeout),
        "login_security":lambda: check_login_security(session, base_url, timeout),
        "feed_enum":     lambda: check_feed_author_enumeration(session, base_url, timeout),
        "woocommerce":   lambda: detect_woocommerce(session, base_url, html, timeout),
        "changelog":     lambda: scan_changelog_version_files(session, base_url, timeout),
        "ajax_nopriv":   lambda: probe_admin_ajax_actions(session, base_url, timeout),
        "pingback":      lambda: check_pingback_ssrf(session, base_url, timeout),
        "app_passwords": lambda: check_application_passwords(session, base_url, timeout),
        "staging":       lambda: detect_staging_environment(session, base_url, html, headers, timeout),
        "uploads":       lambda: scan_uploads_dangerous_files(session, base_url, timeout),
    }

    cb("Deep scan paralelo iniciado...", 5)
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(fn): name for name, fn in modules.items()}
        completed = 0
        try:
            for fut in as_completed(futs, timeout=DEEP_TIMEOUT):
                name = futs[fut]
                completed += 1
                cb(f"Deep scan: {name} completado ({completed}/{len(modules)})",
                   int(5 + 90 * completed / len(modules)))
                try:
                    results[name] = fut.result()
                except Exception as e:
                    log.warning("deep_scan[%s]: %s", name, e)
                    results[name] = {"error": str(e)}
        except FuturesTimeout:
            log.warning("deep_scan: timeout global (%ds) — %d/%d módulos completados",
                        DEEP_TIMEOUT, completed, len(modules))
            for fut, name in futs.items():
                if not fut.done():
                    results[name] = {"error": f"timeout ({DEEP_TIMEOUT}s)"}

    cb("Deep scan completado.", 100)
    return results
"""
WP VulnScanner — Módulo de Análisis Activo
===============================================
ADVERTENCIA: Este módulo realiza pruebas ACTIVAS contra el objetivo.
Solo usar con autorización EXPRESA del propietario del sitio.
Uso sin autorización es ilegal (Art. 264 CP).

Capacidades:
  - Enumeración profunda de usuarios
  - Detección de WAF
  - Fingerprinting de plugins ocultos (probing directo)
  - Detección de versiones por timing
  - Check de archivos de backup con patrones
  - Test de inyección básica (SQLi, XSS reflejado)
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional, Callable
from urllib.parse import urljoin

import requests

                                                                      
from scanner.utils import xml_safe, detect_waf_from_response

log = logging.getLogger("wpvulnscan.active")

                                                                               
WP_TOP_PASSWORDS = [
    "admin", "password", "123456", "admin123", "wordpress",
    "pass", "1234", "12345678", "qwerty", "letmein",
    "admin1234", "root", "toor", "test", "demo",
    "changeme", "welcome", "login", "master", "dragon",
    "monkey", "shadow", "sunshine", "princess", "abc123",
    "iloveyou", "654321", "superman", "mustang", "access",
]

WP_TOP_USERNAMES = [
    "admin", "administrator", "user", "test", "demo",
    "webmaster", "editor", "author", "manager", "wordpress",
    "wp", "root", "info", "contact", "support",
]

                                                                             
                                                                      
HIDDEN_PLUGINS_PROBE = [
                                                                                
    "wordfence", "really-simple-ssl", "loginizer", "two-factor",
    "google-authenticator", "limit-login-attempts-reloaded",
    "all-in-one-wp-security-and-firewall", "sucuri-scanner",
    "wp-cerber", "ithemes-security", "bulletproof-security",
    "wp-hide-login", "miniOrange-2-factor-authentication",
    "jetpack-protect", "shield-security", "security-ninja",
    "wp-simple-firewall", "anti-spam", "akismet",
                                                                                
    "elementor", "elementor-pro", "divi-builder", "beaver-builder-lite-version",
    "beaver-builder", "brizy", "oxygen", "bricks-builder", "wpbakery",
    "visual-composer", "fusion-builder", "cornerstone",
    "themify-builder", "page-builder-by-siteorigin", "live-composer-page-builder",
    "king-composer", "js-composer", "qode-framework",
                                                                                
    "wordpress-seo", "yoast-seo", "all-in-one-seo-pack", "rank-math",
    "rankmath", "seo-by-rank-math", "seo-press", "the-seo-framework",
    "squirrly-seo", "google-sitemap-generator", "wp-sitemap-page",
    "xml-sitemap-generator-for-google", "wp-meta-seo",
                                                                                
    "woocommerce", "woocommerce-payments", "woocommerce-gateway-stripe",
    "woocommerce-gateway-paypal-powered-by-braintree",
    "easy-digital-downloads", "give", "wpforms", "wpforms-lite",
    "ninja-forms", "gravityforms", "caldera-forms", "formidable",
    "contact-form-7", "contact-form-cfdb7", "booking", "amelia",
    "woo-gutenberg-products-block", "wc-vendors", "dokan-lite",
                                                                                
    "wp-super-cache", "w3-total-cache", "litespeed-cache", "wp-rocket",
    "comet-cache", "cache-enabler", "hummingbird-performance",
    "wp-optimize", "autoptimize", "wp-fastest-cache",
    "imagify", "smush", "ewww-image-optimizer", "shortpixel-image-optimiser",
    "async-javascript", "wp-asset-clean-up",
                                                                                
    "updraftplus", "backwpup", "duplicator", "all-in-one-wp-migration",
    "wp-db-backup", "blogvault", "backupwordpress",
    "jetpack", "vaultpress", "wponlinebackup",
                                                                               
    "memberpress", "learndash", "wplms", "learnpress", "tutor",
    "buddypress", "bbpress", "buddyboss-platform",
    "restrict-content-pro", "paid-memberships-pro", "s2member",
    "lifter-lms", "academy-lms", "masteriyo",
                                                                                
    "wp-mail-smtp", "mailchimp-for-wp", "sendinblue", "mailpoet",
    "newsletter", "convertkit-for-woocommerce", "fluentcrm",
    "post-smtp", "easy-wp-smtp", "gmail-smtp",
                                                                                
    "hello-dolly", "classic-editor",
    "advanced-custom-fields", "acf-pro", "metabox", "pods",
    "tablepress", "polylang", "wpml", "translatepress",
    "the-events-calendar", "events-manager", "wp-event-manager",
    "nextgen-gallery", "gallery-by-envira", "modula-best-grid-gallery",
    "revslider", "smart-slider-3", "master-slider", "soliloquy",
    "social-warfare", "social-snap", "wp-social-sharing",
    "mailchimp-for-woocommerce", "constant-contact-forms",
    "hubspot", "salesforce-wordpress-to-lead",
                                                                                
    "popup-builder", "sumo", "optinmonster", "icegram", "ninja-popups",
    "wpdiscuz", "disqus-comment-system", "comments-evolved",
    "loginpress", "theme-my-login",
    "ajax-search-lite", "relevanssi", "wp-search-with-algolia",
    "posts-table-pro", "data-tables-generator-by-supsystic",
    "cookie-law-info", "gdpr-cookie-consent", "complianz-gdpr",
    "wp-smushit",
    "monarch", "bloom", "divi",
    "tawkto-live-chat", "live-chat", "tidio-live-chat", "crisp",
                                                                                
    "query-monitor", "debug-bar", "log-deprecated-notices",
    "health-check", "wp-crontrol", "wp-cli",
    "user-role-editor", "capability-manager-enhanced",
    "simple-history", "stream",
    "cloudflare", "sg-cachepress", "siteground-optimizer",
    "cloudinary-image-management-and-manipulation-in-the-cloud-cdn",
                                                                                
    "genesis", "kadence-blocks", "generateblocks", "stackable-ultimate-gutenberg-blocks",
    "ultimate-addons-for-gutenberg", "spectra", "otter-blocks",
    "responsive-addons-for-elementor", "essential-addons-for-elementor-lite",
    "premium-addons-for-elementor", "jeg-elementor-kit",
                                                                                
    "wordfence-login-security", "wps-hide-login", "rename-wp-login",
    "miniOrange-otp-verification",
    "cloudflare-stream", "amazon-s3-and-cloudfront",
    "wp-stateless", "media-library-assistant",
    "redirection", "404-to-301", "simple-301-redirects",
    "broken-link-checker", "link-checker-seo",
    "wp-fastest-cache-premium", "perfmatters", "flying-pages",
                                                                              
    "wp-file-manager", "wp-statistics", "download-manager",
    "wp-database-backup", "wp-dbmanager",
    "google-analytics-for-wordpress", "google-analytics-dashboard-for-wp",
    "wp-google-maps", "google-maps-widget",
    "booking-calendar", "easy-appointments", "booked",
    "slider-revolution", "revolution-slider",
    "ultimate-member", "user-registration", "profile-builder",
    "forminator", "fluent-forms", "ws-form",
    "wpcf7-redirect", "contact-form-7-honeypot",
    "ad-inserter", "advanced-ads", "wp-insert",
    "wp-photo-album-plus", "photospace", "envira-gallery",
    "feed-them-social", "instagram-feed", "smash-balloon-social-photo-feed",
    "easy-table-of-contents", "wp-table-of-contents",
    "coming-soon", "under-construction-page", "maintenance",
    "wp-maintenance-mode", "wp-maintenance",
    "duplicate-post", "yoast-duplicate-post", "duplicate-page",
    "post-duplicator", "copy-delete-posts",
    "wp-embed-facebook", "facebook-for-woocommerce",
    "header-footer-code-manager", "insert-headers-and-footers",
    "wp-code-manager", "header-and-footer-scripts",
    "woo-discount-rules", "discount-rules-for-woocommerce",
    "yith-woocommerce-wishlist", "ti-woocommerce-wishlist",
    "woocommerce-product-addons", "product-configurator-for-woocommerce",
    "checkout-field-editor-for-woocommerce", "woocommerce-checkout-manager",
    "woocommerce-multilingual", "woocommerce-currency-switcher",
    "stripe-payments", "paypal-for-woocommerce",
    "multivendorx", "wcfm-marketplace",
    "the-plus-addons-for-elementor-page-builder", "happy-elementor-addons",
    "elementor-addon-elements", "addons-for-elementor",
    "dynamic-content-for-elementor", "elementor-extras",
    "wp-twitter-feed", "custom-twitter-feeds",
    "subscribe2", "wysija-newsletters",
    "cforms2", "quform", "machform",
    "motopress-content-editor", "tailor-page-builder",
    "cherry-plugin", "themepunch-tools",
    "maxbuttons", "button-generator", "cssigniter-shortcodes",
    "shortcodes-ultimate", "really-simple-captcha",
    "spam-free-wordpress", "anti-spam-bee",
    "xml-rpc-api", "json-api", "wp-json-api",
    "rest-api-toolbox", "disable-rest-api",
    "wps-bidouille", "wp-super-edit", "tinymce-advanced",
    "file-manager-advanced", "filebird",
    "wpvivid-backups", "backup-guard", "backuply",
    "solid-security", "patchstack",
    "activity-log", "wp-activity-log",
    "metorik-helper", "jetpack-crm",
    "translatepress-multilingual", "wpml-media",
    "woocommerce-amazon-affiliates", "amazon-auto-links",
    "affiliate-wp", "slicewp",
    "fast-velocity-minify",
    "wpdatatables", "tablepress-datatables-extension",
    "advanced-access-manager", "members", "user-access-manager",
    "loco-translate", "codestyling-localization",
]

                                                                     
                                                                                      


@dataclass
class BruteforceResult:
    found:       bool = False
    username:    str  = ""
    password:    str  = ""
    attempts:    int  = 0
    blocked_at:  int  = 0                             
    waf_detected: str = ""
    method:      str  = ""                        

    def to_dict(self) -> dict:
        return vars(self)


@dataclass
class ActiveScanResult:
    bruteforce:          Optional[BruteforceResult] = None
    waf_detected:        str  = ""
    waf_details:         dict = field(default_factory=dict)
    hidden_plugins:      list = field(default_factory=list)
    deep_users:          list = field(default_factory=list)
    backup_files:        list = field(default_factory=list)
    timing_versions:     dict = field(default_factory=dict)
    injection_findings:  list = field(default_factory=list)
    errors:              list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "bruteforce":         self.bruteforce.to_dict() if self.bruteforce else None,
            "waf_detected":       self.waf_detected,
            "waf_details":        self.waf_details,
            "hidden_plugins":     self.hidden_plugins,
            "deep_users":         self.deep_users,
            "backup_files":       self.backup_files,
            "timing_versions":    self.timing_versions,
            "injection_findings": self.injection_findings,
            "errors":             self.errors,
        }


                                                                                

def detect_waf(session: requests.Session, base_url: str, timeout: int = 8) -> tuple[str, dict]:
    """
    Detecta WAF por cabeceras, cookies y respuesta a payloads.
    FIX M3: Usa detect_waf_from_response() de utils.py (firmas centralizadas).
    """
    details = {}
    detected_list = []

    try:
        r = session.get(base_url, timeout=timeout)
        cookies_str = str(r.cookies).lower()

                                                   
        detected_list = detect_waf_from_response(dict(r.headers), r.text, cookies_str)
        if detected_list:
            for waf in detected_list:
                details[waf] = "Firma detectada (cabeceras/cuerpo/cookies)"

                                                                         
        if not detected_list:
            probe_url = urljoin(base_url, "/?s=<script>alert(1)</script>")
            try:
                r2 = session.get(probe_url, timeout=timeout)
                if r2.status_code in (403, 406, 501):
                    detected_list = ["WAF genérico"]
                    details["genérico"] = f"HTTP {r2.status_code} ante payload XSS"
                elif "access denied" in r2.text.lower() or "blocked" in r2.text.lower():
                    detected_list = ["WAF genérico"]
                    details["genérico"] = "Respuesta 'blocked/denied' ante payload"
            except Exception as _e:
                log.debug("active.py excepción silenciada: %s", _e)

    except Exception as _e:
        log.debug("active.py excepción silenciada: %s", _e)

    detected = detected_list[0] if detected_list else ""
    return detected, details


                                                                               

def enumerate_users_deep(session: requests.Session, base_url: str,
                          timeout: int = 8,
                          progress_cb: Optional[Callable] = None) -> list[dict]:
    """Enumeración profunda: REST API, author redirect, XMLRPC, sitemap, RSS."""
    users: dict[str, dict] = {}

    def add_user(login: str, uid: int = 0, display: str = "", source: str = ""):
        key = login.lower()
        if key not in users:
            users[key] = {"login": login, "id": uid,
                          "display_name": display, "source": source}

                                               
    for page in range(1, 5):
        try:
            url = urljoin(base_url, f"/wp-json/wp/v2/users?per_page=100&page={page}")
            r = session.get(url, timeout=timeout)
            if r.status_code != 200:
                break
            data = r.json()
            if not isinstance(data, list) or not data:
                break
            for u in data:
                add_user(u.get("slug", ""), u.get("id", 0),
                         u.get("name", ""), "rest-api")
        except Exception:
            break

    if progress_cb:
        progress_cb("Enumeración usuarios: REST API completada", 0)

                                   
    for uid in range(1, 21):
        try:
            r = session.get(urljoin(base_url, f"/?author={uid}"),
                            timeout=timeout, allow_redirects=True)
            m = re.search(r'/author/([^/?"\'<>\s]+)', r.url)
            if m and r.status_code == 200:
                add_user(m.group(1), uid, source="author-redirect")
        except Exception as _e:
            log.debug("active.py excepción silenciada: %s", _e)

    if progress_cb:
        progress_cb("Enumeración usuarios: author redirect completada", 0)

                         
    for feed_url in ["/?feed=rss2", "/?feed=atom", "/feed/", "/comments/feed/"]:
        try:
            r = session.get(urljoin(base_url, feed_url), timeout=timeout)
            if r.status_code == 200:
                for m in re.finditer(r'<dc:creator><!\[CDATA\[([^\]]+)\]\]>', r.text):
                    add_user(m.group(1).strip(), source="rss-feed")
                for m in re.finditer(r'<name>([^<]{3,50})</name>', r.text):
                    name = m.group(1).strip()
                    if name and ' ' not in name:                     
                        add_user(name, source="atom-feed")
        except Exception as _e:
            log.debug("active.py excepción silenciada: %s", _e)

                    
    for sitemap in ["/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml"]:
        try:
            r = session.get(urljoin(base_url, sitemap), timeout=timeout)
            if r.status_code == 200 and "author" in r.text:
                for m in re.finditer(r'/author/([a-z0-9_-]+)/', r.text):
                    add_user(m.group(1), source="sitemap")
        except Exception as _e:
            log.debug("active.py excepción silenciada: %s", _e)

                                                                         
    try:
        payload = """<?xml version="1.0"?>
<methodCall><methodName>wp.getAuthors</methodName>
<params><param><value><int>1</int></value></param>
<param><value><string></string></value></param>
<param><value><string></string></value></param>
</params></methodCall>"""
        r = session.post(urljoin(base_url, "/xmlrpc.php"),
                         data=payload,
                         headers={"Content-Type": "text/xml"},
                         timeout=timeout)
        if r.status_code == 200:
            for m in re.finditer(r'<value><string>([a-zA-Z0-9_.-]+)</string></value>', r.text):
                val = m.group(1)
                if 3 < len(val) < 40 and not val.startswith("http"):
                    add_user(val, source="xmlrpc-authors")
    except Exception as _e:
        log.debug("active.py excepción silenciada: %s", _e)

    return list(users.values())


                                                                                

def bruteforce_login(session: requests.Session, base_url: str,
                     usernames: list[str], passwords: list[str],
                     timeout: int = 8,
                     max_attempts: int = 100,
                     progress_cb: Optional[Callable] = None) -> BruteforceResult:
    """
    Intenta credenciales contra /wp-login.php y XMLRPC.
    Se detiene si detecta bloqueo (429, CAPTCHA, lockout message).
    """
    result = BruteforceResult()
    login_url = urljoin(base_url, "/wp-login.php")
    attempts  = 0

                                              
    redirect_to = urljoin(base_url, "/wp-admin/")
    try:
        r = session.get(login_url, timeout=timeout)
        m = re.search(r'name="redirect_to"\s+value="([^"]+)"', r.text)
        if m:
            redirect_to = m.group(1)
    except Exception as _e:
        log.debug("active.py excepción silenciada: %s", _e)

    LOCKOUT_SIGNALS = [
        "too many failed", "locked out", "too many login",
        "error: too many", "blocked", "captcha",
        "security check", "slow down",
    ]

                                                                            
                                                                   
    _consecutive_errors = 0
    _base_delay         = 0.8                                                    
    _max_delay          = 15.0                    

    for username in usernames:
        for password in passwords:
            if attempts >= max_attempts:
                break

            attempts += 1
            if progress_cb and attempts % 5 == 0:
                progress_cb(
                    f"Fuerza bruta: {attempts} intentos ({username}:{'*'*len(password)})", 0)

            try:
                r = session.post(login_url, data={
                    "log":         username,
                    "pwd":         password,
                    "wp-submit":   "Log In",
                    "redirect_to": redirect_to,
                    "testcookie":  "1",
                }, timeout=timeout, allow_redirects=False)

                                                 
                if r.status_code in (301, 302):
                    location = r.headers.get("Location", "")
                    if "wp-admin" in location or "dashboard" in location:
                        result.found    = True
                        result.username = username
                        result.password = password
                        result.attempts = attempts
                        result.method   = "form"
                        return result

                                        
                body_lower = r.text.lower()
                if r.status_code == 429:
                    result.blocked_at = attempts
                    return result
                for signal in LOCKOUT_SIGNALS:
                    if signal in body_lower:
                        result.blocked_at = attempts
                        return result

                                                                          
                if r.status_code in (503, 429) or r.elapsed.total_seconds() > 5:
                    _consecutive_errors += 1
                    delay = min(_base_delay * (2 ** _consecutive_errors), _max_delay)
                    log.debug("BF backoff: %ds (errores consecutivos=%d)", delay, _consecutive_errors)
                    time.sleep(delay)
                else:
                    _consecutive_errors = max(0, _consecutive_errors - 1)
                    time.sleep(_base_delay)

            except requests.exceptions.RequestException:
                _consecutive_errors += 1
                delay = min(_base_delay * (2 ** _consecutive_errors), _max_delay)
                time.sleep(delay)
                continue

        if attempts >= max_attempts:
            break

    result.attempts = attempts

                                                          
    if not result.found and usernames:
        xmlrpc_url = urljoin(base_url, "/xmlrpc.php")
        for username in usernames[:3]:                                 
            for password in passwords[:10]:
                try:
                                                                                    
                                                                                                
                    safe_user = xml_safe(username)
                    safe_pass = xml_safe(password)
                    payload = f"""<?xml version="1.0"?>
<methodCall><methodName>wp.getProfile</methodName>
<params>
  <param><value><int>1</int></value></param>
  <param><value><string>{safe_user}</string></value></param>
  <param><value><string>{safe_pass}</string></value></param>
</params></methodCall>"""
                    r = session.post(xmlrpc_url, data=payload,
                                     headers={"Content-Type": "text/xml"},
                                     timeout=timeout)
                    if r.status_code == 200 and "<fault>" not in r.text and "user_login" in r.text:
                        result.found    = True
                        result.username = username
                        result.password = password
                        result.method   = "xmlrpc"
                        return result
                    time.sleep(0.5)
                except Exception as _e:
                    log.debug("active.py excepción silenciada: %s", _e)

    return result


                                                                                

def probe_hidden_plugins(session: requests.Session, base_url: str,
                          known_slugs: set[str], timeout: int = 6,
                          progress_cb: Optional[Callable] = None) -> list[dict]:
    """Prueba directamente si existen plugins que no aparecen en el HTML."""
    found = []
    slugs_to_probe = [s for s in HIDDEN_PLUGINS_PROBE if s not in known_slugs]

    def probe(slug: str) -> Optional[dict]:
        import random, time as _t
        _t.sleep(random.uniform(0.2, 0.6))                    
        for path in [
            f"/wp-content/plugins/{slug}/readme.txt",
            f"/wp-content/plugins/{slug}/README.txt",
            f"/wp-content/plugins/{slug}/{slug}.php",
        ]:
            try:
                r = session.get(urljoin(base_url, path),
                                timeout=timeout, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 20:
                    version = None
                    m = re.search(r'(?:Stable tag|Version):\s*([0-9][0-9a-zA-Z._-]*)', r.text, re.I)
                    if m:
                        version = m.group(1)
                    return {"slug": slug, "version": version,
                            "detected_via": f"direct-probe:{path}", "confidence": 85, "type": "plugin"}
            except Exception as _e:
                log.debug("active.py excepción silenciada: %s", _e)
        return None

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=4) as ex:                              
        futures = {ex.submit(probe, slug): slug for slug in slugs_to_probe}
        done = 0
        for future in as_completed(futures):
            done += 1
            result = future.result()
            if result:
                found.append(result)
            if progress_cb and done % 10 == 0:
                progress_cb(f"Probing plugins ocultos: {done}/{len(slugs_to_probe)}", 0)

    return found


                                                                                

BACKUP_PATTERNS = []
for _domain_hint in ["{domain}", "wordpress", "wp", "backup", "site", "web"]:
    for _ext in [".zip", ".tar.gz", ".tar", ".sql", ".gz", ".bak", ".old"]:
        for _prefix in ["/", "/wp-content/", "/backup/", "/backups/"]:
            BACKUP_PATTERNS.append(f"{_prefix}{_domain_hint}{_ext}")


def find_backup_files(session: requests.Session, base_url: str,
                       domain: str, timeout: int = 6) -> list[dict]:
    """Busca archivos de backup con nombre del dominio."""
    found = []
    domain_clean = domain.replace("www.", "").split(".")[0]

    patterns = []
    for p in BACKUP_PATTERNS:
        patterns.append(p.replace("{domain}", domain_clean))
                                   
    import datetime
    y = datetime.datetime.now().year
    for ext in [".zip", ".sql", ".tar.gz"]:
        patterns.append(f"/{domain_clean}-{y}{ext}")
        patterns.append(f"/{domain_clean}_{y}{ext}")
        patterns.append(f"/backup-{y}{ext}")
        patterns.append(f"/db-backup{ext}")

    def check(path: str) -> Optional[dict]:
        import random, time as _t
        _t.sleep(random.uniform(0.2, 0.5))                    
        try:
            url = urljoin(base_url, path)
            r = session.head(url, timeout=timeout, allow_redirects=False)
            if r.status_code == 200:
                size = r.headers.get("Content-Length", "?")
                return {"path": path, "url": url,
                        "size": size, "severity": "critical",
                        "description": "Posible archivo de backup accesible"}
        except Exception as _e:
            log.debug("active.py excepción silenciada: %s", _e)
        return None

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=4) as ex:                               
        for result in as_completed([ex.submit(check, p) for p in patterns]):
            r = result.result()
            if r:
                found.append(r)

    return found


                                                                                

INJECTION_TESTS = [
                                                         
    ("XSS reflejado en búsqueda",  "/?s=",        None,  "<script>alert(1)</script>", "<script>alert(1)</script>"),
    ("SQLi en búsqueda",           "/?s=",        None,  "' OR '1'='1",               "SQL syntax"),
    ("LFI en path",                "/?page=",     None,  "../../../etc/passwd",        "root:"),
    ("Open redirect",              "/?redirect=", None,  "https://evil.com",           "evil.com"),
    ("XXE en xmlrpc",              "/xmlrpc.php", "xml", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", "root:"),
]


def test_basic_injections(session: requests.Session, base_url: str,
                           timeout: int = 6) -> list[dict]:
    """Tests básicos de inyección — solo detecta, no explota."""
    findings = []
    for desc, path, _param, payload, signal in INJECTION_TESTS:
        try:
            url = urljoin(base_url, path + requests.utils.quote(payload))
            r = session.get(url, timeout=timeout)
            if signal.lower() in r.text.lower():
                findings.append({
                    "type":        desc,
                    "url":         url,
                    "payload":     payload,
                    "severity":    "high",
                    "description": f"Posible {desc} — señal '{signal}' encontrada en respuesta",
                })
        except Exception as _e:
            log.debug("active.py excepción silenciada: %s", _e)
    return findings


                                                                                

class ActiveScanner:

    def __init__(self, session: requests.Session, base_url: str,
                 timeout: int = 8,
                 known_plugins: Optional[list] = None,
                 known_users: Optional[list] = None):
        self.session        = session
        self.base_url       = base_url
        self.timeout        = timeout
        self.known_plugins  = known_plugins or []
        self.known_users    = known_users or []
        from urllib.parse import urlparse
        self.domain = urlparse(base_url).hostname or ""

    def run(self,
            do_bruteforce: bool = True,
            do_deep_enum:  bool = True,
            do_hidden_plugins: bool = True,
            do_backups:    bool = True,
            do_injections: bool = False,                           
            max_bf_attempts: int = 60,
            progress_cb: Optional[Callable] = None) -> ActiveScanResult:
                                                                  
        try:
            return self._run_impl(
                do_bruteforce=do_bruteforce, do_deep_enum=do_deep_enum,
                do_hidden_plugins=do_hidden_plugins, do_backups=do_backups,
                do_injections=do_injections, max_bf_attempts=max_bf_attempts,
                progress_cb=progress_cb,
            )
        except Exception as _run_err:
            log.error("ActiveScanner.run() error inesperado: %s", _run_err, exc_info=True)
            r = ActiveScanResult()
            r.errors.append(f"Error inesperado en análisis activo: {_run_err}")
            return r

    def _run_impl(self,
            do_bruteforce: bool = True,
            do_deep_enum:  bool = True,
            do_hidden_plugins: bool = True,
            do_backups:    bool = True,
            do_injections: bool = False,
            max_bf_attempts: int = 60,
            progress_cb: Optional[Callable] = None) -> ActiveScanResult:

        result = ActiveScanResult()

        def cb(msg, pct):
            if progress_cb:
                progress_cb(msg, pct)

                
        cb("Detectando WAF...", 0)
        result.waf_detected, result.waf_details = detect_waf(
            self.session, self.base_url, self.timeout)
        if result.waf_detected:
            cb(f"WAF detectado: {result.waf_detected}", 0)

                                             
        if do_deep_enum:
            cb("Enumeración profunda de usuarios...", 0)
            result.deep_users = enumerate_users_deep(
                self.session, self.base_url, self.timeout, cb)
            cb(f"Usuarios encontrados: {len(result.deep_users)}", 0)

                            
        if do_hidden_plugins:
            cb("Probando plugins ocultos (probing directo)...", 0)
            known = {p.get("slug","") if isinstance(p, dict) else getattr(p,"slug","")
                     for p in self.known_plugins}
            result.hidden_plugins = probe_hidden_plugins(
                self.session, self.base_url, known, self.timeout, cb)
            if result.hidden_plugins:
                cb(f"Plugins ocultos encontrados: {len(result.hidden_plugins)}", 0)

                    
        if do_backups:
            cb("Buscando archivos de backup...", 0)
            result.backup_files = find_backup_files(
                self.session, self.base_url, self.domain, self.timeout)
            if result.backup_files:
                cb(f"⚠ Backups encontrados: {len(result.backup_files)}", 0)

                                
        if do_injections:
            cb("Tests de inyección básica...", 0)
            result.injection_findings = test_basic_injections(
                self.session, self.base_url, self.timeout)

                                                                    
                                                                            
        _ = do_bruteforce
        _ = max_bf_attempts

        return result

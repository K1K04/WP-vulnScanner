"""
WP VulnScanner — Nuevos módulos de detección v5.4
======================================================
Implementa los checks de seguridad nuevos:
  - CORS misconfiguration en /wp-json/
  - WP_DEBUG activo en producción
  - TLS/cipher suite analysis (TLS 1.0/1.1, RC4, 3DES)
  - Detección de wp-login personalizado (hide-login)
  - wp-cron abusable externamente (POST real)
  - WordPress Multisite detection
  - REST API sin autenticación (datos privados/emails)
  - Redirect chain analysis (Googlebot UA)
  - Plugin timing detection (baseline estadístico)
  - Inyecciones POST con nonce discovery
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

log = logging.getLogger("wpvulnscan.new_detections")

UA_NORMAL    = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36")
UA_GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


                                                                               
                                              
                                                                               

POST_INJECTION_TESTS = [
                                              
                                                                                           
    ("XSS POST en login",     "/wp-login.php",           "log",      "<svg/onload=1>", "svg/onload"),
    ("SQLi POST en login",    "/wp-login.php",           "log",      "' OR '1'='1",               "SQL syntax"),
    ("XSS POST en búsqueda",  "/?s=",                    None,       "<img src=x onerror=1>",     "onerror=1"),
    ("Open redirect POST",    "/wp-login.php",           "redirect_to", "https://evil.example.com", "evil.example"),
    ("LFI POST en acción",    "/wp-admin/admin-ajax.php","action",   "../../../../etc/passwd",    "root:x:"),
]


def _discover_nonce(session: requests.Session, base_url: str, timeout: int = 6) -> str:
    """Extrae nonce del formulario de login de WordPress."""
    try:
        r = session.get(urljoin(base_url, "/wp-login.php"), timeout=timeout)
        m = re.search(r'name="([a-z_]+nonce[a-z_]*)"[^>]+value="([a-f0-9]+)"', r.text, re.I)
        if m:
            return m.group(2)
                                                              
        m2 = re.search(r'name="_wpnonce" value="([a-f0-9]+)"', r.text)
        if m2:
            return m2.group(1)
    except Exception as e:
        log.debug("nonce discovery: %s", e)
    return ""


def test_post_injections(session: requests.Session, base_url: str,
                          timeout: int = 7) -> list[dict]:
    """
    Tests de inyección vía POST — incluye nonce discovery y formularios WP reales.
    Complementa los tests GET de test_basic_injections().
    """
    findings: list[dict] = []
    nonce = _discover_nonce(session, base_url, timeout)

    for desc, endpoint, field, payload, signal in POST_INJECTION_TESTS:
        try:
            url  = urljoin(base_url, endpoint)
            data: dict = {}

            if endpoint == "/wp-login.php":
                data = {
                    "log": "testuser", "pwd": "testpass",
                    "wp-submit": "Log+In", "redirect_to": "/wp-admin/",
                    "testcookie": "1",
                }
                if nonce:
                    data["_wpnonce"] = nonce
                if field:
                    data[field] = payload
            elif endpoint == "/wp-admin/admin-ajax.php":
                data = {"action": payload, "nonce": nonce or ""}
            else:
                data = {field or "data": payload}

            r = session.post(url, data=data, timeout=timeout, allow_redirects=True)
            if signal.lower() in r.text.lower():
                findings.append({
                    "type":        desc,
                    "url":         url,
                    "method":      "POST",
                    "payload":     payload,
                    "field":       field,
                    "severity":    "high",
                    "description": f"Posible {desc} via POST — señal '{signal}' en respuesta",
                })
        except Exception as e:
            log.debug("post_injection: %s", e)

    return findings


                                                                               
                                             
                                                                               

def check_cors_misconfiguration(session: requests.Session, base_url: str,
                                  timeout: int = 7) -> dict:
    """
    Detecta misconfiguraciones CORS en la REST API de WordPress.
    Un Access-Control-Allow-Origin: * permite exfiltración de datos.
    """
    result = {
        "vulnerable": False,
        "severity": "none",
        "findings": [],
    }

    _SEV_ORDER = ["none", "info", "low", "medium", "high", "critical"]

    def _upgrade_severity(current: str, new_sev: str) -> str:
        """Devuelve la severidad más alta entre current y new_sev."""
        return new_sev if _SEV_ORDER.index(new_sev) > _SEV_ORDER.index(current) else current

    endpoints = [
        "/wp-json/",
        "/wp-json/wp/v2/posts",
        "/wp-json/wp/v2/users",
    ]

    evil_origins = [
        "https://evil.example.com",
        "null",
    ]

    for endpoint in endpoints:
        url = urljoin(base_url, endpoint)
        endpoint_found = False                                          
        for origin in evil_origins:
            try:
                r = session.get(url, timeout=timeout,
                                headers={"Origin": origin})
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

                if acao == "*" and not endpoint_found:
                    endpoint_found = True
                    result["vulnerable"] = True
                    result["severity"]   = _upgrade_severity(result["severity"], "medium")
                    result["findings"].append({
                        "endpoint": endpoint,
                        "issue":    "Access-Control-Allow-Origin: * (wildcard)",
                        "severity": "medium",
                        "impact":   "Permite lectura de la REST API desde cualquier dominio",
                    })
                    break                                           

                if acao and acao != "null" and origin in acao and not endpoint_found:
                    endpoint_found = True
                    issue = {
                        "endpoint": endpoint,
                        "issue":    f"ACAO refleja origen arbitrario: {acao}",
                        "severity": "high",
                        "impact":   "Reflect-Origin CORS — posible exfiltración de datos autenticados",
                    }
                    if acac == "true":
                        issue["severity"] = "critical"
                        issue["impact"]  += " + credenciales incluidas (ACAC: true)"
                    result["vulnerable"] = True
                    result["severity"]   = _upgrade_severity(result["severity"], issue["severity"])
                    result["findings"].append(issue)

            except Exception as e:
                log.debug("cors_check: %s", e)

    return result


                                                                               
                                                     
                                                                               

DEBUG_PATTERNS = [
                      
    r'<br\s*/?>(\s*\n)?\s*#\d+\s+[A-Z]:\\',
    r'<br\s*/?>(\s*\n)?\s*#\d+\s+/[a-z/]',
    r'PHP\s+(Warning|Notice|Fatal|Deprecated)',
    r'Call\s+Stack.*#\d',
    r'Stack\s+trace:',
                                         
    r'<!--.*?/home/\w+/.*?-->',
    r'<!--.*?/var/www/.*?-->',
    r'<!--.*?wp-content/.*?\.php.*?-->',
                                           
    r'Notice:\s+Undefined\s+(variable|index)',
    r'Warning:\s+include\(',
    r'Fatal error:.*?on line \d+',
                                              
    r'id="qm-"\s',
    r'class="debug-bar',
]

_DEBUG_RE = [re.compile(p, re.I | re.DOTALL) for p in DEBUG_PATTERNS]


def detect_wp_debug(session: requests.Session, base_url: str,
                     timeout: int = 8) -> dict:
    """
    Detecta WP_DEBUG=true activo en producción analizando la homepage y
    rutas adicionales en busca de stack traces y mensajes de error PHP.
    """
    result = {
        "debug_active":  False,
        "severity":      "none",
        "indicators":    [],
    }

    urls_to_check = [
        base_url,
        urljoin(base_url, "/?p=99999999"),                       
        urljoin(base_url, "/wp-login.php"),
        urljoin(base_url, "/wp-admin/"),
    ]

    for url in urls_to_check:
        try:
            r = session.get(url, timeout=timeout)
            text = r.text

            for pat in _DEBUG_RE:
                m = pat.search(text)
                if m:
                    snippet = m.group(0)[:120].replace("\n", " ").strip()
                    result["debug_active"] = True
                    result["severity"]     = "high"
                    result["indicators"].append({
                        "url":     url,
                        "pattern": pat.pattern[:60],
                        "snippet": snippet,
                    })

        except Exception as e:
            log.debug("wp_debug_check: %s", e)

    if result["debug_active"]:
        result["description"] = (
            "WP_DEBUG=true detectado en producción. Expone rutas internas, "
            "versiones de PHP/plugins y stack traces en el HTML público."
        )

    return result


                                                                               
                                    
                                                                               

WEAK_CIPHERS = {
    "RC4", "RC2", "DES", "3DES", "MD5", "NULL", "EXPORT",
    "aNULL", "eNULL", "ADH", "AECDH",
}

DEPRECATED_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}


def analyze_tls(hostname: str, port: int = 443) -> dict:
    """
    Analiza TLS: versión del protocolo, cipher suites débiles,
    HSTS preloading y si hay Mixed Content en el HTML.
    """
    result = {
        "tls_version":          None,
        "cipher_suite":         None,
        "weak_cipher":          False,
        "deprecated_protocol":  False,
        "weak_protocol_list":   [],
        "hsts_preload":         False,
        "certificate_info":     {},
        "findings":             [],
        "severity":             "none",
    }

    if not hostname:
        return result

    ctx_default = ssl.create_default_context()
    ctx_legacy  = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx_legacy.check_hostname = False
    ctx_legacy.verify_mode    = ssl.CERT_NONE

                                                           
    try:
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx_default.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher    = ssock.cipher()                       
                tls_ver   = ssock.version()
                cert      = ssock.getpeercert()

                result["tls_version"]  = tls_ver
                result["cipher_suite"] = cipher[0] if cipher else None
                result["certificate_info"] = {
                    "subject":      dict(x[0] for x in cert.get("subject", [])),
                    "issuer":       dict(x[0] for x in cert.get("issuer",  [])),
                    "not_after":    cert.get("notAfter", ""),
                }

                                          
                not_after_str = cert.get("notAfter", "")
                if not_after_str:
                    try:
                                                                                          
                                                                                          
                        not_after_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        not_after_dt = not_after_dt.replace(tzinfo=timezone.utc)
                        days_left = (not_after_dt - datetime.now(timezone.utc)).days
                        result["certificate_info"]["days_until_expiry"] = days_left
                        if days_left < 0:
                            result["findings"].append({
                                "issue":    f"Certificado SSL expirado hace {abs(days_left)} días",
                                "severity": "critical",
                            })
                            result["severity"] = "critical"
                        elif days_left < 15:
                            result["findings"].append({
                                "issue":    f"Certificado SSL expira en {days_left} días — renovar urgentemente",
                                "severity": "high",
                            })
                            if result["severity"] not in ("critical",):
                                result["severity"] = "high"
                        elif days_left < 30:
                            result["findings"].append({
                                "issue":    f"Certificado SSL expira en {days_left} días",
                                "severity": "medium",
                            })
                            if result["severity"] not in ("critical", "high"):
                                result["severity"] = "medium"
                    except Exception as _e:
                        log.debug("non-critical path suppressed: %s", _e)

                                       
                cipher_name = (cipher[0] or "").upper()
                for weak in WEAK_CIPHERS:
                    if weak in cipher_name:
                        result["weak_cipher"] = True
                        result["severity"]    = "high"
                        result["findings"].append({
                            "issue":    f"Cipher débil en uso: {cipher[0]}",
                            "severity": "high",
                        })
                        break

                if tls_ver in DEPRECATED_PROTOCOLS:
                    result["deprecated_protocol"] = True
                    result["severity"]            = "high"
                    result["findings"].append({
                        "issue":    f"Protocolo deprecado activo: {tls_ver}",
                        "severity": "high",
                        "cwe":      "CWE-326",
                    })

    except ssl.SSLError as e:
        result["findings"].append({"issue": f"SSL error: {e}", "severity": "medium"})
    except Exception as e:
        log.debug("tls_analysis: %s", e)

                                         
    for proto_name, proto_const in [("TLSv1", ssl.TLSVersion.TLSv1),
                                     ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]:
        try:
            ctx_old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_old.check_hostname = False
            ctx_old.verify_mode    = ssl.CERT_NONE
            ctx_old.minimum_version = proto_const
            ctx_old.maximum_version = proto_const
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx_old.wrap_socket(sock, server_hostname=hostname):
                    result["deprecated_protocol"] = True
                    result["weak_protocol_list"].append(proto_name)
                    result["severity"] = "high"
                    result["findings"].append({
                        "issue":    f"{proto_name} aceptado por el servidor (deprecado por IETF RFC 8996)",
                        "severity": "high",
                        "cwe":      "CWE-326",
                    })
        except Exception:
            pass                                     

    return result


def check_tls_full(session: requests.Session, base_url: str,
                   timeout: int = 10) -> dict:
    """Wrapper que extrae hostname y ejecuta analyze_tls + HSTS preload check."""
    parsed   = urlparse(base_url)
    hostname = parsed.hostname or ""
    port     = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        return {
            "tls_version": None, "cipher_suite": None,
            "weak_cipher": False, "deprecated_protocol": False,
            "weak_protocol_list": [], "hsts_preload": False,
            "findings": [{"issue": "Sitio sin HTTPS — no hay TLS", "severity": "critical"}],
            "severity": "critical",
        }

    result = analyze_tls(hostname, port)

                                                                    
    try:
        r = session.get(f"https://hstspreload.org/api/v2/status?domain={hostname}",
                        timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            result["hsts_preload"] = data.get("status") == "preloaded"
    except Exception as e:
        log.debug("HSTS preload check failed for %s: %s", hostname, e)

                                                              
    try:
        r2 = session.get(base_url, timeout=timeout)
        mc = re.findall(r'src=["\']http://[^"\']+["\']', r2.text)
        if mc:
            result["findings"].append({
                "issue":    f"Mixed Content detectado ({len(mc)} recursos HTTP en página HTTPS)",
                "severity": "medium",
                "examples": mc[:3],
            })
            if result["severity"] == "none":
                result["severity"] = "medium"
    except Exception as e:
        log.debug("Mixed content check failed: %s", e)

    return result


                                                                               
                                                           
                                                                               

CUSTOM_LOGIN_CANDIDATES = [
    "/acceder", "/admin", "/login", "/acceso",
    "/portal", "/signin", "/backend", "/wpadmin",
]


def detect_custom_login_url(session: requests.Session, base_url: str,
                              timeout: int = 7) -> dict:
    """
    Detecta si wp-login.php ha sido movido (plugin WPS Hide Login, etc).
    Estrategias:
      1. Busca action= del form en la homepage
      2. Analiza robots.txt buscando Disallow con slugs típicos de login
      3. Prueba candidatos comunes con HEAD request
    """
    result = {
        "original_accessible": False,
        "custom_url":          None,
        "detection_method":    None,
        "hide_login_plugin":   False,
    }

                                                   
    try:
        r = session.get(urljoin(base_url, "/wp-login.php"), timeout=timeout,
                        allow_redirects=False)
        if r.status_code == 200 and "wp-submit" in r.text:
            result["original_accessible"] = True
            return result                  
        if r.status_code == 404:
            result["hide_login_plugin"] = True
    except Exception as e:
        log.debug("custom_login check: %s", e)

                                      
    try:
        r = session.get(base_url, timeout=timeout)
        m = re.search(r'action=["\']([^"\']+/(?:login|acceder|entrar|signin|wp)[^"\']*)["\']',
                      r.text, re.I)
        if m:
            custom = m.group(1)
            result["custom_url"]       = custom
            result["detection_method"] = "form-action-homepage"
            return result
    except Exception as e:
        log.debug("custom_login homepage: %s", e)

                            
    try:
        r = session.get(urljoin(base_url, "/robots.txt"), timeout=timeout)
        if r.status_code == 200:
            for line in r.text.splitlines():
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    for cand in CUSTOM_LOGIN_CANDIDATES:
                        if cand.lower() in path.lower():
                            result["custom_url"]       = path
                            result["detection_method"] = "robots-disallow"
                            return result
    except Exception as e:
        log.debug("custom_login robots: %s", e)

                                   
    for cand in CUSTOM_LOGIN_CANDIDATES:
        try:
            url = urljoin(base_url, cand)
            r   = session.get(url, timeout=4, allow_redirects=True)
            if r.status_code == 200 and (
                "wp-submit" in r.text or
                "log" in r.text.lower() and "pwd" in r.text.lower()
            ):
                result["custom_url"]       = cand
                result["detection_method"] = "direct-probe"
                return result
        except Exception as e:
            log.debug("Login probe %s: %s", cand, e)

    return result


                                                                               
                                        
                                                                               

def check_wp_cron_abuse(session: requests.Session, base_url: str,
                         timeout: int = 10) -> dict:
    """
    Verifica si /wp-cron.php es accesible y abusable externamente.
    Hace un POST con doing_wp_cron=1 y mide el tiempo de respuesta.
    Un delay > 2s con respuesta no-404 indica cron ejecutándose.
    """
    result = {
        "accessible":       False,
        "abusable":         False,
        "response_time_ms": None,
        "status_code":      None,
        "x_wp_cron_header": False,
        "severity":         "none",
    }

    url = urljoin(base_url, "/wp-cron.php")

                             
    try:
        r_head = session.head(url, timeout=6, allow_redirects=False)
        if r_head.status_code == 404:
            return result             
    except Exception as e:
        log.debug("wp_cron HEAD: %s", e)
        return result

                            
    try:
        t0 = time.monotonic()
        r  = session.post(url, data={"doing_wp_cron": "1"},
                          timeout=timeout, allow_redirects=False)
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        result["accessible"]       = r.status_code not in (404, 403, 301, 302, 307, 308)
        result["status_code"]      = r.status_code
        result["response_time_ms"] = elapsed_ms
        result["x_wp_cron_header"] = "x-wp-cron" in {k.lower() for k in r.headers}

        if result["accessible"]:
            result["abusable"] = True
            result["severity"] = "medium"
            if elapsed_ms > 2000:
                result["severity"] = "high"                                 
                result["abusable"] = True

    except requests.Timeout:
        result["accessible"]       = True
        result["abusable"]         = True
        result["response_time_ms"] = timeout * 1000
        result["severity"]         = "high"
    except Exception as e:
        log.debug("wp_cron POST: %s", e)

    return result


                                                                               
                                        
                                                                               

def detect_multisite(session: requests.Session, base_url: str,
                      timeout: int = 7) -> dict:
    """
    Detecta instalaciones WordPress Multisite.
    Superficie de ataque ampliada: subdominios de red, ms-files.php, etc.
    """
    result = {
        "is_multisite":          False,
        "subdomain_install":     False,
        "subdirectory_install":  False,
        "indicators":            [],
        "exposed_endpoints":     [],
    }

    checks = {
        "/wp-signup.php":         "wp-signup accesible",
        "/wp-activate.php":       "wp-activate accesible",
        "/wp-admin/network/":     "red de administración",
        "/files/":                "ms-files endpoint",
    }

    for path, desc in checks.items():
        try:
            url = urljoin(base_url, path)
            r   = session.get(url, timeout=timeout, allow_redirects=True)
            if r.status_code in (200, 302, 301):
                result["indicators"].append(desc)
                result["exposed_endpoints"].append({
                    "path": path, "status": r.status_code, "description": desc
                })
                if path == "/wp-admin/network/":
                    result["is_multisite"] = True
        except Exception as e:
            log.debug("multisite check %s: %s", path, e)

                                                                      
                                                                           
    try:
        r = session.get(base_url, timeout=timeout)
        html = r.text
                                               
        if "wp-signup.php" in html:
            result["indicators"].append("wp-signup.php referenciado en homepage")
        if re.search(r'href=["\'][^"\']*?/wp-signup\.php', html, re.I):
            result["indicators"].append("enlace wp-signup.php en página principal")
            result["is_multisite"] = True
                                                                            
        if re.search(r'/sites/\d+/', html):
            result["indicators"].append("ruta /sites/N/ detectada — subdirectorio multisite")
            result["subdirectory_install"] = True
            result["is_multisite"] = True
        if re.search(r'/blog/wp-(?:content|includes|admin)/', html):
            result["indicators"].append("subsite /blog/ con estructura WordPress")
            result["subdirectory_install"] = True
    except Exception as e:
        log.debug("multisite homepage: %s", e)

                                             
    try:
        r = session.head(urljoin(base_url, "/wp-json/"), timeout=timeout)
        link = r.headers.get("Link", "")
        if "network" in link.lower() or "main_site" in link.lower():
            result["is_multisite"] = True
            result["indicators"].append("Link header revela red multisite")
    except Exception as e:
        log.debug("multisite Link header: %s", e)

    if len(result["indicators"]) >= 2:
        result["is_multisite"] = True

    return result


                                                                               
                                     
                                                                               

def check_rest_api_auth(session: requests.Session, base_url: str,
                         timeout: int = 7) -> dict:
    """
    Verifica si la REST API expone datos privados sin autenticación:
      - Posts/páginas en borrador o privadas
      - Emails de usuarios
      - Edición con context=edit sin token
    """
    result = {
        "exposes_emails":         False,
        "exposes_private_posts":  False,
        "allows_edit_context":    False,
        "findings":               [],
        "severity":               "none",
    }

                                  
    try:
        r = session.get(urljoin(base_url, "/wp-json/wp/v2/users?per_page=10"),
                        timeout=timeout)
        if r.status_code == 200:
            users = r.json()
            if isinstance(users, list):
                for u in users:
                    if u.get("email") and "@" in u.get("email", ""):
                        result["exposes_emails"] = True
                        result["severity"]        = "high"
                        result["findings"].append({
                            "endpoint": "/wp-json/wp/v2/users",
                            "issue":    f"Email expuesto sin auth: {u['email'][:30]}...",
                            "severity": "high",
                        })
                        break
    except Exception as e:
        log.debug("rest_api_users: %s", e)

                                                 
    for ctype in ["posts", "pages"]:
        try:
            r = session.get(urljoin(base_url, f"/wp-json/wp/v2/{ctype}?status=any&per_page=20"),
                            timeout=timeout)
            if r.status_code == 200:
                items = r.json()
                if isinstance(items, list):
                    for item in items:
                        if item.get("status") in ("draft", "private", "pending"):
                            result["exposes_private_posts"] = True
                            result["severity"]               = "high"
                            result["findings"].append({
                                "endpoint": f"/wp-json/wp/v2/{ctype}",
                                "issue":    f"Contenido '{item['status']}' expuesto sin auth (ID: {item.get('id')})",
                                "severity": "high",
                            })
                            break
        except Exception as e:
            log.debug("rest_api_%s: %s", ctype, e)

                               
    try:
        r = session.get(urljoin(base_url, "/wp-json/wp/v2/posts?context=edit&per_page=1"),
                        timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list) and data and "content" in data[0]:
                raw = data[0].get("content", {}).get("raw", "")
                if raw:
                    result["allows_edit_context"] = True
                    result["severity"]             = "critical"
                    result["findings"].append({
                        "endpoint": "/wp-json/wp/v2/posts?context=edit",
                        "issue":    "context=edit devuelve contenido RAW sin autenticación",
                        "severity": "critical",
                    })
    except Exception as e:
        log.debug("rest_api_edit_context: %s", e)

    return result


                                                                               
                                                  
                                                                               

def check_redirect_chains(session: requests.Session, base_url: str,
                            timeout: int = 8) -> dict:
    """
    Detecta redirecciones encubiertas que solo ocurren con User-Agents específicos.
    Un sitio comprometido redirige a dominios maliciosos para Googlebot o mobile,
    pero sirve contenido normal a navegadores normales.
    """
    result = {
        "suspicious":          False,
        "normal_final_url":    None,
        "googlebot_final_url": None,
        "mobile_final_url":    None,
        "discrepancies":       [],
        "severity":            "none",
    }

    def get_final_url(ua: str, label: str) -> Optional[str]:
        try:
            import os as _os
            _verify = _os.getenv("VERIFY_SSL", "false").lower() not in ("false", "0", "no")
            s = requests.Session()
            s.headers.update({"User-Agent": ua})
            try:
                r = s.get(base_url, timeout=timeout, allow_redirects=True, verify=_verify)
                return r.url
            except Exception as e:
                log.debug("redirect_chain %s: %s", label, e)
                return None
            finally:
                s.close()
        except Exception as e:
            log.debug("redirect_chain %s: %s", label, e)
            return None

    normal_url    = get_final_url(UA_NORMAL, "normal")
    googlebot_url = get_final_url(UA_GOOGLEBOT, "googlebot")
    mobile_url    = get_final_url(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15",
        "mobile"
    )

    result["normal_final_url"]    = normal_url
    result["googlebot_final_url"] = googlebot_url
    result["mobile_final_url"]    = mobile_url

    base_parsed = urlparse(base_url)
    base_domain = base_parsed.netloc

    for label, final_url in [("Googlebot", googlebot_url), ("Mobile", mobile_url)]:
        if not final_url or not normal_url:
            continue
        if final_url != normal_url:
            final_parsed = urlparse(final_url)
            if final_parsed.netloc and final_parsed.netloc != base_domain:
                result["suspicious"] = True
                result["severity"]   = "critical"
                result["discrepancies"].append({
                    "agent":     label,
                    "normal":    normal_url,
                    "different": final_url,
                    "issue":     f"Redirección diferente para {label}: {final_url} — posible malware/SEO poisoning",
                    "severity":  "critical",
                })
            else:
                                                                      
                result["discrepancies"].append({
                    "agent":     label,
                    "normal":    normal_url,
                    "different": final_url,
                    "issue":     f"URL final diferente para {label} (mismo dominio)",
                    "severity":  "info",
                })

    return result


                                                                               
                                   
                                                                               

def detect_plugins_by_timing(session: requests.Session, base_url: str,
                               plugin_slugs: list[str],
                               timeout: int = 5,
                               min_samples: int = 3) -> list[dict]:
    """
    Detecta plugins ocultos mediante análisis estadístico de tiempo de respuesta.
    Plugins que existen tardan ligeramente más (acceso al FS real).
    Establece un baseline con rutas inexistentes y detecta outliers.
    """
    if len(plugin_slugs) < 5:
        return []

                                                        
    baseline_slugs = [f"_fake_plugin_{i}_nonexistent_xyz" for i in range(3)]
    baseline_times: list[float] = []

    for slug in baseline_slugs:
        url = urljoin(base_url, f"/wp-content/plugins/{slug}/readme.txt")
        try:
            t0 = time.monotonic()
            session.get(url, timeout=timeout)
            baseline_times.append(time.monotonic() - t0)
        except Exception:
            baseline_times.append(timeout)

    if not baseline_times:
        return []

    mean_baseline = statistics.mean(baseline_times)
    stdev = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0.05
    threshold    = mean_baseline + max(stdev * 2, 0.15)                     

                                                                  
    found: list[dict] = []
    lock = threading.Lock()

    def probe(slug: str):
        url  = urljoin(base_url, f"/wp-content/plugins/{slug}/readme.txt")
        times: list[float] = []
                                                                                
        _ps = requests.Session()
        _ps.headers.update(session.headers)
        try:
            for _ in range(min_samples):
                try:
                    t0 = time.monotonic()
                    r  = _ps.get(url, timeout=timeout)
                    elapsed = time.monotonic() - t0
                                                              
                    if r.status_code == 403:
                        times.append(elapsed)
                    elif r.status_code == 404:
                        times.append(elapsed)
                    else:
                        times.append(elapsed)
                except Exception:
                    times.append(timeout)
        finally:
            _ps.close()

        if not times:
            return

        avg = statistics.mean(times)
        if avg > threshold:
            with lock:
                found.append({
                    "slug":             slug,
                    "avg_response_ms":  int(avg * 1000),
                    "baseline_ms":      int(mean_baseline * 1000),
                    "threshold_ms":     int(threshold * 1000),
                    "confidence":       min(int(((avg - mean_baseline) / threshold) * 80), 95),
                    "detection_method": "timing-analysis",
                    "note":             "Detectado por timing (diferencia estadística respecto al baseline)",
                })

    with ThreadPoolExecutor(max_workers=5) as ex:                                    
        list(ex.map(probe, plugin_slugs[:100]))                                

    return found


                                                                               
                                         
                                                                               

                                                                             
_BACKUP_PATTERNS = [
                       
    "backup.zip", "backup.tar.gz", "backup.sql", "backup.sql.gz",
    "backup.sql.bz2", "dump.sql", "db.sql", "database.sql",
    "site.zip", "wordpress.zip", "wp-backup.zip",
                       
    "wp-content/updraft/",
    "wp-content/ai1wm-backups/",
    "wp-content/backups/",
    "wp-content/backupwordpress/",
    "wp-content/backups-dup-lite/",
                                   
    "backup_2024.zip", "backup_2025.zip", "backup_2023.zip",
    "www.zip", "public_html.zip", "html.zip",
                   
    "wp-config.bak", "wp-config.php.bak", "wp-config.php.orig",
    "wp-config.php~", "wp-config.php.old", "wp-config.php.save",
                       
    "error_log", "php_error.log", "wordpress_debug.log",
    "wp-content/debug.log", "wp-content/error.log",
    ".env", ".env.bak", ".env.prod", ".env.local",
                                   
    ".git/config", ".git/HEAD", ".git/COMMIT_EDITMSG",
    ".gitignore", ".svn/entries",
                      
    "phpinfo.php", "info.php", "test.php", "phptest.php",
                             
    "install.php", "setup.php", "wp-admin/setup-config.php",
                                     
    "db_backup.sql", "mysql.sql", "wordpress.sql",
    "data.sql", "export.sql",
]

_BACKUP_SEVERITY = {
    "wp-config": "critical",
    ".env":      "critical",
    ".git":      "critical",
    "backup.sql": "critical",
    "dump.sql":  "critical",
    "database":  "critical",
    "phpinfo":   "high",
    "install.php": "high",
    "error_log": "medium",
    "debug.log": "medium",
    ".gitignore": "low",
}


def _get_backup_severity(path: str) -> str:
    path_lower = path.lower()
    for key, sev in _BACKUP_SEVERITY.items():
        if key in path_lower:
            return sev
    if path.endswith((".sql", ".sql.gz", ".zip", ".tar.gz", ".bak")):
        return "high"
    return "medium"


def scan_backup_files(
    session: requests.Session,
    base_url: str,
    timeout: int = 7,
    skip_paths: set | None = None,
) -> dict:
    """
    Módulo #7: Escáner de backups y archivos sensibles ampliado.
    Busca backups, dumps SQL, archivos .env, repositorios Git expuestos,
    instaladores residuales y archivos de debug en rutas conocidas.

    FIX-6: Acepta skip_paths — conjunto de rutas ya sondeadas por
    check_exposed_files() en core.py. Las rutas en skip_paths se omiten
    para evitar peticiones HTTP duplicadas al mismo servidor.
    """
    _skip = skip_paths or set()
    result: dict = {
        "exposed": [],
        "severity": "none",
        "git_exposed": False,
        "env_exposed": False,
        "sql_dump_exposed": False,
        "config_exposed": False,
    }
    sev_order = ["none", "low", "medium", "high", "critical"]

    def _probe(path: str) -> None:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                                                                                      
        import random
        time.sleep(random.uniform(0.3, 0.9))
                                                                       
        _s = requests.Session()
        _s.headers.update(session.headers)
        try:
            r = _s.head(url, timeout=timeout, allow_redirects=False)
            status = r.status_code
            if status == 405:
                r2 = _s.get(url, timeout=timeout, allow_redirects=False,
                                 stream=True)
                status = r2.status_code
                r2.close()
            if status == 200:
                sev = _get_backup_severity(path)
                entry = {"path": path, "url": url, "severity": sev}

                                        
                p = path.lower()
                if ".git" in p:
                    result["git_exposed"] = True
                    entry["note"] = "Repositorio Git expuesto — puede filtrar código fuente y credenciales"
                elif ".env" in p:
                    result["env_exposed"] = True
                    entry["note"] = "Archivo .env expuesto — puede contener claves API y credenciales"
                elif any(x in p for x in [".sql", "dump", "database", "db_"]):
                    result["sql_dump_exposed"] = True
                    entry["note"] = "Dump SQL expuesto — contiene datos de la base de datos"
                elif "wp-config" in p:
                    result["config_exposed"] = True
                    entry["note"] = "Archivo de configuración WordPress expuesto"
                elif "install.php" in p or "setup.php" in p:
                    entry["note"] = "Instalador residual accesible — permite reinstalar WordPress"
                elif "phpinfo" in p or "info.php" in p:
                    entry["note"] = "phpinfo() expone versiones, rutas y configuración del servidor"

                result["exposed"].append(entry)

                if sev_order.index(sev) > sev_order.index(result["severity"]):
                    result["severity"] = sev

                log.info("Backup/sensitive file exposed: %s (%s)", url, sev)
        except Exception as e:
            log.debug("Backup probe %s: %s", path, e)
        finally:
            _s.close()

    with ThreadPoolExecutor(max_workers=3) as ex:                                              
                                                                   
        to_probe = [p for p in _BACKUP_PATTERNS
                    if "/" + p.lstrip("/") not in _skip and p not in _skip]
        list(ex.map(_probe, to_probe))

    return result


                                                                               
                                                                      
                                                                               

                                                                     
                                                                                
_JS_SIGNATURES = [
            
    ("jQuery", r"jquery[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js", {
        "critical": [],
        "high": ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6",
                 "1.7", "1.8", "1.9", "1.10", "1.11", "1.12"],
        "medium": ["2.0", "2.1", "2.2", "3.0", "3.1", "3.2", "3.3", "3.4"],
    }, "CVE-2019-11358,CVE-2020-11022,CVE-2020-11023",
       "jQuery < 3.5.0 vulnerable a XSS via $.htmlPrefilter"),

               
    ("Bootstrap", r"bootstrap[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js", {
        "high": ["2.0", "2.1", "2.2", "2.3", "3.0", "3.1", "3.2", "3.3"],
        "medium": ["3.4.0", "3.4.1", "4.0", "4.1", "4.2", "4.3"],
    }, "CVE-2019-8331,CVE-2018-14042",
       "Bootstrap < 4.3.1 vulnerable a XSS"),

            
    ("Lodash", r"lodash[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js", {
        "critical": ["4.0.0", "4.1.0", "4.2.0", "4.3.0", "4.4.0",
                     "4.5.0", "4.6.0", "4.7.0", "4.8.0", "4.9.0",
                     "4.10.0", "4.11.0", "4.12.0", "4.13.0", "4.14.0",
                     "4.15.0", "4.16.0", "4.17.0", "4.17.1", "4.17.2",
                     "4.17.3", "4.17.4", "4.17.5", "4.17.6", "4.17.7",
                     "4.17.8", "4.17.9", "4.17.10"],
    }, "CVE-2019-10744,CVE-2020-8203",
       "Lodash < 4.17.21 vulnerable a Prototype Pollution"),

               
    ("Moment.js", r"moment[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js", {
        "high": ["2.0.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0",
                 "2.5.0", "2.6.0", "2.7.0", "2.8.0", "2.9.0",
                 "2.10.0", "2.11.0", "2.12.0", "2.13.0", "2.14.0",
                 "2.15.0", "2.16.0", "2.17.0", "2.18.0", "2.19.0",
                 "2.20.0", "2.21.0", "2.22.0", "2.23.0", "2.24.0",
                 "2.25.0", "2.26.0", "2.27.0"],
    }, "CVE-2022-24785,CVE-2016-4055",
       "Moment.js < 2.29.2 vulnerable a ReDoS y path traversal"),

                   
    ("Underscore.js", r"underscore[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js", {
        "high": ["1.8.3", "1.9.0", "1.9.1", "1.10.0", "1.10.1",
                 "1.10.2", "1.11.0", "1.12.0", "1.12.1"],
    }, "CVE-2021-23358",
       "Underscore.js < 1.13.0 vulnerable a Arbitrary Code Execution"),

             
    ("Angular", r"angular[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js", {
        "critical": ["1.0.0","1.0.1","1.0.2","1.0.3","1.0.4","1.0.5","1.0.6","1.0.7","1.0.8",
                     "1.1.0","1.1.1","1.1.2","1.1.3","1.1.4","1.1.5",
                     "1.2.0","1.2.1","1.2.2","1.2.3","1.2.4","1.2.5","1.2.6","1.2.7",
                     "1.2.8","1.2.9","1.2.10","1.2.11","1.2.12","1.2.13","1.2.14",
                     "1.2.15","1.2.16","1.2.17","1.2.18","1.2.19","1.2.20",
                     "1.3.0","1.3.1","1.3.2","1.3.3","1.3.4","1.3.5","1.3.6","1.3.7",
                     "1.3.8","1.3.9","1.3.10","1.3.11","1.3.12","1.3.13","1.3.14",
                     "1.4.0","1.4.1","1.4.2","1.4.3","1.4.4","1.4.5","1.4.6","1.4.7",
                     "1.5.0","1.5.1","1.5.2","1.5.3","1.5.4","1.5.5","1.5.6","1.5.7",
                     "1.5.8","1.5.9","1.5.10","1.5.11"],
        "high":     ["1.6.0","1.6.1","1.6.2","1.6.3","1.6.4","1.6.5","1.6.6","1.6.7",
                     "1.6.8","1.6.9","1.7.0","1.7.1","1.7.2","1.7.3","1.7.4","1.7.5",
                     "1.7.6","1.7.7","1.7.8","1.7.9"],
    }, "CVE-2019-10768,CVE-2020-7676",
       "AngularJS < 1.8.0 vulnerable a XSS / template injection"),

               
    ("DOMPurify", r"dompurify[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js", {
        "high":   ["1.0.0","1.0.1","1.0.2","1.0.3","1.0.4","1.0.5","1.0.6","1.0.7",
                   "1.0.8","1.0.9","1.0.10","1.0.11"],
        "medium": ["2.0.0","2.0.1","2.0.2","2.0.3","2.0.4","2.0.5","2.0.6","2.0.7",
                   "2.0.8","2.0.9","2.0.10","2.0.11","2.0.12","2.0.13","2.0.14",
                   "2.0.15","2.0.16","2.0.17"],
    }, "CVE-2020-26870,CVE-2019-25094",
       "DOMPurify < 2.1.0 vulnerable a XSS bypass"),

           
    ("Axios", r"axios[.-]?(\d+\.\d+\.\d+)(?:\.min)?\.js", {
        "high":   ["0.18.0","0.18.1","0.19.0","0.19.1"],
        "medium": ["0.20.0","0.21.0","0.21.1"],
    }, "CVE-2020-28168,CVE-2021-3749",
       "Axios < 0.21.2 vulnerable a SSRF y ReDoS"),
]

                                    
_KNOWN_CDNS = {
            
    "ajax.googleapis.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "storage.googleapis.com", "www.google.com", "www.googletagmanager.com",
    "www.google-analytics.com", "ssl.google-analytics.com",
                
    "cdnjs.cloudflare.com", "cdn.cloudflare.com",
                                 
    "cdn.jsdelivr.net", "unpkg.com", "esm.sh",
            
    "code.jquery.com",
               
    "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
    "cdn.rawgit.com",
                  
    "use.fontawesome.com", "cdn.fontawesome.com", "ka-f.fontawesome.com",
                           
    "cdn.datatables.net", "cdn.tiny.cloud",
               
    "momentjs.com",
                                      
    "js.stripe.com", "js.paypal.com",
    "connect.facebook.net", "platform.twitter.com",
    "cdn.segment.com", "cdn.amplitude.com",
                        
    "s0.wp.com", "s1.wp.com", "s2.wp.com",
    "i0.wp.com", "i1.wp.com", "i2.wp.com",
    "c0.wp.com",
                       
    "ajax.aspnetcdn.com",
}


def analyze_js_dependencies(
    session: requests.Session,
    base_url: str,
    html_content: str = "",
    timeout: int = 8,
) -> dict:
    """
    Módulo #8: Análisis de dependencias JS (Retire.js approach).
    Detecta librerías JS vulnerables en scripts cargados por la página,
    identifica CDNs no reconocidos y analiza integridad SRI.
    """
    result: dict = {
        "vulnerable_libs":  [],
        "unknown_cdn_srcs": [],
        "missing_sri":      [],
        "external_scripts": [],
        "severity":         "none",
        "score_delta":      0,
    }
    sev_order = ["none", "low", "medium", "high", "critical"]

                                
    if not html_content:
        try:
            r = session.get(base_url, timeout=timeout)
            html_content = r.text
        except Exception as e:
            log.warning("JS analysis: could not fetch page: %s", e)
            return result

                                        
    script_srcs = re.findall(
        r'<script[^>]+src=["\']([^"\']+)["\']', html_content, re.IGNORECASE
    )

    result["external_scripts"] = [s for s in script_srcs if s.startswith("http")]

                                                  
    script_tags = re.findall(
        r'<script[^>]+src=["\']https?://[^"\']+["\'][^>]*>', html_content, re.IGNORECASE
    )
    for tag in script_tags:
        if "integrity=" not in tag:
            src_match = re.search(r'src=["\']([^"\']+)["\']', tag)
            if src_match:
                result["missing_sri"].append({
                    "url":  src_match.group(1),
                    "note": "Script externo sin atributo integrity (SRI) — vulnerable a supply chain attack",
                    "severity": "medium",
                })

                                
    from urllib.parse import urlparse as _urlparse
    for src in result["external_scripts"]:
        domain = _urlparse(src).netloc
        if domain and domain not in _KNOWN_CDNS:
                                       
            own_domain = _urlparse(base_url).netloc
            if domain != own_domain:
                result["unknown_cdn_srcs"].append({
                    "url":    src,
                    "domain": domain,
                    "note":   f"Script cargado desde dominio externo no reconocido: {domain}",
                    "severity": "low",
                })

                                                             
    for lib_name, version_re, affected_versions, cves, description in _JS_SIGNATURES:
        for src in script_srcs:
            m = re.search(version_re, src, re.IGNORECASE)
            if not m:
                                                               
                continue
            version = m.group(1)
            major_minor = ".".join(version.split(".")[:2])

            found_sev = None
            for sev, versions in affected_versions.items():
                if version in versions or major_minor in versions:
                    found_sev = sev
                    break

            if found_sev:
                result["vulnerable_libs"].append({
                    "library":     lib_name,
                    "version":     version,
                    "src":         src,
                    "severity":    found_sev,
                    "cves":        cves,
                    "description": description,
                })
                if sev_order.index(found_sev) > sev_order.index(result["severity"]):
                    result["severity"] = found_sev
                result["score_delta"] += {
                    "critical": 15, "high": 10, "medium": 5, "low": 2
                }.get(found_sev, 0)
                log.info("Vulnerable JS library: %s %s (%s)", lib_name, version, found_sev)

    return result


                                                                               
                                               
                                                                               

def enumerate_users_advanced(
    session: requests.Session,
    base_url: str,
    timeout: int = 8,
) -> dict:
    """
    Módulo #15: Enumeración avanzada de usuarios WordPress.
    Combina múltiples técnicas más allá de /?author=N:
      - REST API /wp-json/wp/v2/users
      - oEmbed API
      - Feed RSS/Atom (author tags)
      - Sitemap XML
      - Login hints (mensajes de error diferenciados)
      - Comentarios HTML (wp:comment-author)
    """
    result: dict = {
        "users":                   [],
        "techniques_used":         [],
        "login_enumerable":        False,
        "author_archive_enumerable": False,
        "severity":                "none",
        "score_delta":             0,
    }

    found_logins: set = set()

    def _add_user(login: str, display: str = "", email: str = "",
                  source: str = "", url: str = "") -> None:
        if login in found_logins:
            return
        found_logins.add(login)
        entry: dict = {
            "login":        login,
            "display_name": display or login,
            "source":       source,
            "url":          url,
        }
        if email:
            entry["email"] = email
        result["users"].append(entry)

                                                                                
    try:
        url = urljoin(base_url, "/wp-json/wp/v2/users?per_page=100")
        r = session.get(url, timeout=timeout)
        if r.status_code == 200:
            users_data = r.json()
            if isinstance(users_data, list) and users_data:
                result["techniques_used"].append("rest-api")
                for u in users_data:
                    _add_user(
                        login   = u.get("slug", ""),
                        display = u.get("name", ""),
                        email   = u.get("email", ""),
                        source  = "REST API",
                        url     = u.get("link", ""),
                    )
    except Exception as e:
        log.debug("REST API user enum: %s", e)

                                                                                
    try:
                                             
        r = session.get(urljoin(base_url, "/feed/"), timeout=timeout)
        post_urls = re.findall(r'<link>(https?://[^<]+)</link>', r.text)
        for post_url in post_urls[:3]:
            oembed_url = urljoin(base_url,
                                 f"/wp-json/oembed/1.0/embed?url={post_url}")
            r2 = session.get(oembed_url, timeout=timeout)
            if r2.status_code == 200:
                data = r2.json()
                author = data.get("author_name", "")
                author_url = data.get("author_url", "")
                if author:
                                                 
                    slug_m = re.search(r"/author/([^/]+)/?", author_url)
                    slug = slug_m.group(1) if slug_m else author.lower().replace(" ", "")
                    _add_user(login=slug, display=author,
                              source="oEmbed", url=author_url)
                    result["techniques_used"].append("oembed")
    except Exception as e:
        log.debug("oEmbed user enum: %s", e)

                                                                                
    try:
        for feed_url in ["/feed/", "/?feed=rss2", "/?feed=atom"]:
            r = session.get(urljoin(base_url, feed_url), timeout=timeout)
            if r.status_code != 200:
                continue
                                            
            creators = re.findall(
                r'<dc:creator><!\[CDATA\[([^\]]+)\]\]></dc:creator>', r.text
            )
            creators += re.findall(r'<name>([^<]+)</name>', r.text)
            if creators:
                result["techniques_used"].append("rss-feed")
                for name in set(creators):
                    name = name.strip()
                    if name and len(name) < 60:
                        slug = name.lower().replace(" ", "-")
                        _add_user(login=slug, display=name,
                                  source="RSS Feed")
            break
    except Exception as e:
        log.debug("RSS user enum: %s", e)

                                                                                
    try:
        for sm_url in ["/sitemap.xml", "/sitemap_index.xml", "/author-sitemap.xml"]:
            r = session.get(urljoin(base_url, sm_url), timeout=timeout)
            if r.status_code != 200:
                continue
            author_urls = re.findall(r'<loc>(https?://[^<]*/author/([^/<]+)/?)</loc>', r.text)
            if author_urls:
                result["techniques_used"].append("sitemap")
                for full_url, slug in author_urls:
                    _add_user(login=slug, source="Sitemap XML", url=full_url)
    except Exception as e:
        log.debug("Sitemap user enum: %s", e)

                                                                                
    found_author_ids = []
    for author_id in range(1, 6):
        try:
            url = urljoin(base_url, f"/?author={author_id}")
            r = session.get(url, timeout=timeout, allow_redirects=True)
            if r.status_code == 200 and "/author/" in r.url:
                slug_m = re.search(r"/author/([^/]+)/?", r.url)
                if slug_m:
                    slug = slug_m.group(1)
                    _add_user(login=slug, source="author-redirect",
                              url=r.url)
                    found_author_ids.append(author_id)
                    result["author_archive_enumerable"] = True
                    if "author-redirect" not in result["techniques_used"]:
                        result["techniques_used"].append("author-redirect")
        except Exception as e:
            log.debug("Author redirect %d: %s", author_id, e)

                                                                                
    try:
                                                                                 
                                                
        fake_user = "xzqwerty99fake"
        r_fake = session.post(
            urljoin(base_url, "/wp-login.php"),
            data={"log": fake_user, "pwd": "wrongpassword", "wp-submit": "Log In",
                  "redirect_to": "/wp-admin/", "testcookie": "1"},
            timeout=timeout,
            allow_redirects=False,
        )
        fake_msg = r_fake.text

                                          
        if found_logins:
            real_user = next(iter(found_logins))
            r_real = session.post(
                urljoin(base_url, "/wp-login.php"),
                data={"log": real_user, "pwd": "wrongpassword", "wp-submit": "Log In",
                      "redirect_to": "/wp-admin/", "testcookie": "1"},
                timeout=timeout,
                allow_redirects=False,
            )
            real_msg = r_real.text

                                                              
            if fake_msg != real_msg:
                result["login_enumerable"] = True
                if "login-error-diff" not in result["techniques_used"]:
                    result["techniques_used"].append("login-error-diff")
    except Exception as e:
        log.debug("Login error diff check: %s", e)

                                                                                
    n = len(result["users"])
    if n > 0:
        result["severity"] = "medium"
        result["score_delta"] = min(n * 3, 15)
    if result["login_enumerable"]:
        result["score_delta"] += 8
    if any(u.get("email") for u in result["users"]):
        result["score_delta"] += 10
        result["severity"] = "high"

    return result


                                                                               
                                                                   
                                                                               

def check_login_protection(session: requests.Session, base_url: str,
                            timeout: int = 8) -> dict:
    """
    Verifica si wp-login.php tiene protección contra fuerza bruta:
    - Sin lockout tras intentos fallidos repetidos
    - User enumeration via diferencia en mensajes de error
    - Rate limiting observable
    """
    result = {
        "login_accessible":     False,
        "no_lockout_detected":  False,
        "user_enum_via_login":  False,
        "rate_limit_detected":  False,
        "severity":             "none",
        "findings":             [],
    }

    login_url = urljoin(base_url, "/wp-login.php")

                    
    try:
        r_head = session.head(login_url, timeout=timeout, allow_redirects=True)
        if r_head.status_code in (404, 410):
            return result                                
        result["login_accessible"] = True
    except Exception as e:
        log.debug("login_protection HEAD: %s", e)
        return result

                                                  
    fake_user = "__wpvs_probe_user__"
    fake_pass = "__wpvs_probe_pass__"
    blocked   = False

    for attempt in range(3):
        try:
            r = session.post(
                login_url,
                data={"log": fake_user, "pwd": fake_pass,
                      "wp-submit": "Log+In", "redirect_to": "/wp-admin/",
                      "testcookie": "1"},
                timeout=timeout, allow_redirects=True,
            )
            if r.status_code in (429, 503):
                result["rate_limit_detected"] = True
                blocked = True
                break
            if any(h in r.headers for h in ("X-Blocked-By", "X-Sucuri-Block",
                                             "X-Wordfence", "X-Fail2Ban")):
                result["rate_limit_detected"] = True
                blocked = True
                break
            body_lower = r.text.lower()
            if any(kw in body_lower for kw in
                   ("too many", "blocked", "lockout", "locked out", "banned",
                    "demasiados intentos", "bloqueado", "cerber", "wordfence")):
                result["rate_limit_detected"] = True
                blocked = True
                break
        except Exception as e:
            log.debug("login_protection attempt %d: %s", attempt, e)
            break

    if not blocked:
        result["no_lockout_detected"] = True
        result["severity"] = "medium"
        result["findings"].append({
            "issue":    "wp-login.php sin señales de lockout tras 3 intentos fallidos",
            "severity": "medium",
            "impact":   "Potencialmente vulnerable a ataques de fuerza bruta",
        })

                                                 
    try:
        r_fake = session.post(
            login_url,
            data={"log": "__nonexistent_user_xyz__", "pwd": "wrongpass123",
                  "wp-submit": "Log+In", "testcookie": "1"},
            timeout=timeout, allow_redirects=True,
        )
        r_admin = session.post(
            login_url,
            data={"log": "admin", "pwd": "wrongpass123",
                  "wp-submit": "Log+In", "testcookie": "1"},
            timeout=timeout, allow_redirects=True,
        )
        fake_body  = r_fake.text.lower()
        admin_body = r_admin.text.lower()

        fake_invalid   = "invalid username" in fake_body or "usuario incorrecto" in fake_body
        admin_wrong_pw = (("incorrect" in admin_body and "admin" in admin_body) or
                          ("contraseña" in admin_body and "incorrecta" in admin_body))

        if fake_invalid and admin_wrong_pw:
            result["user_enum_via_login"] = True
            if result["severity"] == "none":
                result["severity"] = "medium"
            result["findings"].append({
                "issue":    "Enumeración de usuarios via mensajes de error de wp-login.php",
                "severity": "medium",
                "impact":   "Los mensajes de error revelan si un usuario existe (admin confirmado)",
            })
    except Exception as e:
        log.debug("login_protection enum: %s", e)

    return result

                                                                               
                                              
                                                                               

def check_passive_fingerprints(
    session,
    base_url: str,
    html: str,
    resp_headers: dict,
    timeout: int = 8,
) -> dict:
    """
    Nuevas detecciones pasivas que no requieren peticiones activas adicionales.
    Analiza la página principal y sus cabeceras para extraer información sensible
    que normalmente pasa desapercibida.

    Detecta:
      1. Link: <…>; rel="https://api.w.org/" — confirma WP aunque esté oculto
      2. X-Pingback — revela URL xmlrpc aunque el fichero esté renombrado
      3. EditURI / wlwmanifest en HTML — metadata Windows Live Writer
      4. Emails expuestos en el código fuente (mailto: + heurística)
      5. Claves de API / tokens hardcodeados en JS público
      6. Comentarios HTML con rutas internas del servidor
      7. REST API generator version disclosure vía /wp-json/
    """
    

    result = {
        "wp_confirmed_via_link_header": False,
        "pingback_url":                None,
        "wlwmanifest_url":             None,
        "exposed_emails":              [],
        "hardcoded_keys":              [],
        "internal_paths_in_comments":  [],
        "rest_api_version":            None,
        "findings":                    [],
        "severity":                    "none",
    }

    sev_order = ["none", "low", "medium", "high", "critical"]

    def _bump(s: str):
        if sev_order.index(s) > sev_order.index(result["severity"]):
            result["severity"] = s

                                                                              
    link_hdr = resp_headers.get("Link", "") or resp_headers.get("link", "")
    if "api.w.org" in link_hdr:
        result["wp_confirmed_via_link_header"] = True
        result["findings"].append({
            "issue":    "Link header confirma WordPress (api.w.org) — detectable aunque se oculten rutas",
            "severity": "info",
            "detail":   link_hdr[:200],
        })
                                          
        m = re.search(r'<([^>]+)>;\s*rel="https://api\.w\.org/"', link_hdr)
        if m:
            result["rest_api_url"] = m.group(1)

                                                                               
    pingback = resp_headers.get("X-Pingback", "") or resp_headers.get("x-pingback", "")
    if pingback:
        result["pingback_url"] = pingback
        _bump("medium")
        result["findings"].append({
            "issue":    f"X-Pingback revela URL de XML-RPC: {pingback}",
            "severity": "medium",
            "detail":   "El header X-Pingback expone la ruta exacta de xmlrpc.php incluso si ha sido renombrado o movido.",
        })

                                                                               
    if "wlwmanifest" in html:
        m = re.search(r'href=["\']([^"\']*wlwmanifest[^"\']*)["\']', html, re.I)
        if m:
            result["wlwmanifest_url"] = m.group(1)
            result["findings"].append({
                "issue":    "wlwmanifest.xml referenciado en HTML — fingerprinting WordPress",
                "severity": "low",
                "detail":   f"URL: {m.group(1)}. Eliminar con: remove_action('wp_head', 'wlwmanifest_link');",
            })
            _bump("low")

    edituri = re.search(r'<link[^>]+rel=["\']EditURI["\'][^>]*href=["\']([^"\']+)["\']', html, re.I)
    if edituri:
        result["findings"].append({
            "issue":    f"EditURI en HTML confirma WordPress y versión API: {edituri.group(1)[:80]}",
            "severity": "low",
            "detail":   "Eliminar con: remove_action('wp_head', 'rsd_link');",
        })
        _bump("low")

                                                                               
    emails = list(set(re.findall(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        html
    )))
                                     
    skip_domains = {"example.com", "test.com", "domain.com", "wordpress.org",
                    "schema.org", "w3.org", "sentry.io", "googleapis.com"}
    emails = [e for e in emails if e.split("@")[1].lower() not in skip_domains
              and not e.startswith("example") and len(e) < 80][:10]

    if emails:
        result["exposed_emails"] = emails
        _bump("medium")
        result["findings"].append({
            "issue":    f"{len(emails)} email(s) expuesto(s) en HTML público",
            "severity": "medium",
            "detail":   f"Emails: {', '.join(emails[:5])}. Pueden usarse para phishing o ataques de fuerza bruta al login.",
        })

                                                                              
    key_patterns = [
        (r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',  "API key"),
        (r'(?i)(stripe|pk_live|sk_live)_[A-Za-z0-9]{20,}',                                        "Stripe key"),
        (r'(?i)AIza[0-9A-Za-z\-_]{35}',                                                             "Google API key"),
        (r'(?i)(aws_access_key|AKID)[A-Z0-9]{16,}',                                                 "AWS key"),
        (r'(?i)ghp_[A-Za-z0-9]{36}',                                                                "GitHub token"),
    ]
    found_keys = []
    for pattern, key_type in key_patterns:
        m = re.search(pattern, html)
        if m:
            found_keys.append(key_type)
            _bump("critical")
            result["findings"].append({
                "issue":    f"Posible {key_type} hardcodeada en HTML público",
                "severity": "critical",
                "detail":   f"Patrón detectado: {m.group(0)[:60]}…  Revocar y rotar inmediatamente.",
            })
    result["hardcoded_keys"] = found_keys

                                                                               
    internal_paths = re.findall(
        r'<!--.*?(?:/home/|/var/www/|/usr/|C:\\\\|D:\\\\|/srv/)[^\s"\'<>]{5,50}.*?-->',
        html, re.DOTALL
    )
    if internal_paths:
        result["internal_paths_in_comments"] = internal_paths[:3]
        _bump("medium")
        result["findings"].append({
            "issue":    f"Rutas del servidor expuestas en comentarios HTML ({len(internal_paths)} instancias)",
            "severity": "medium",
            "detail":   f"Ejemplo: {internal_paths[0][:100]}. Pueden revelar estructura de directorios al atacante.",
        })

                                                                              
    try:
        r = session.get(urljoin(base_url, "/wp-json/"), timeout=min(timeout, 5))
        if r.status_code == 200 and "application/json" in r.headers.get("Content-Type", ""):
            api_data = r.json()
                                                                    
                                           
            namespaces = api_data.get("namespaces", [])
            wp_ver_m = re.search(r'WordPress ([0-9]+\.[0-9]+(?:\.[0-9]+)?)', str(api_data))
            if wp_ver_m:
                result["rest_api_version"] = wp_ver_m.group(1)
                result["findings"].append({
                    "issue":    f"REST API revela versión WordPress: {wp_ver_m.group(1)}",
                    "severity": "low",
                    "detail":   "Filtrar la respuesta de /wp-json/ o deshabilitar el endpoint si no es necesario.",
                })
                _bump("low")
                                        
            plugin_ns = [ns for ns in namespaces if ns not in ("wp/v2", "oembed/1.0")]
            if plugin_ns:
                result["findings"].append({
                    "issue":    f"REST API revela {len(plugin_ns)} namespace(s) de plugins instalados",
                    "severity": "info",
                    "detail":   f"Namespaces: {', '.join(plugin_ns[:8])}",
                })
    except Exception as _e:
        log.debug("passive_fingerprints rest: %s", _e)

    return result


                                                                               
                                               
                                                                               

                                                                     
_REMEDIATION_DETAIL: dict[str, dict] = {
    "CVE-2023-32243": {
        "title":   "Privilege Escalation sin autenticación",
        "steps": [
            "Actualizar Elementor Pro a ≥ 3.11.7 desde Plugins > Añadir nuevo",
            "WP-CLI: wp plugin update elementor-pro",
            "Verificar logs de acceso por intentos de register/reset_password anómalos",
            "Auditar usuarios administrador creados recientemente: wp user list --role=administrator",
        ],
        "urgency": "INMEDIATA — explotación activa confirmada (CISA KEV)",
    },
    "CVE-2023-3460": {
        "title":   "Escalada de privilegios Ultimate Member",
        "steps": [
            "Actualizar Ultimate Member a ≥ 2.6.7 inmediatamente",
            "WP-CLI: wp plugin update ultimate-member",
            "Auditar usuarios creados en los últimos 30 días: wp user list --orderby=registered",
            "Revisar roles asignados: wp user list --field=roles | sort | uniq -c",
            "Deshabilitar registro de usuarios si no es necesario: Settings > General > Membership",
        ],
        "urgency": "INMEDIATA — explotación masiva documentada en julio 2023",
    },
    "CVE-2024-10924": {
        "title":   "Bypass autenticación 2FA Really Simple SSL",
        "steps": [
            "Actualizar Really Simple SSL a ≥ 9.1.1",
            "WP-CLI: wp plugin update really-simple-ssl",
            "Revisar sesiones activas sospechosas: wp session list (si el plugin lo soporta)",
            "Forzar re-login de todos los usuarios: wp user session destroy --all",
        ],
        "urgency": "INMEDIATA — bypass total de autenticación",
    },
    "CVE-2023-28121": {
        "title":   "Bypass autenticación WooCommerce Payments",
        "steps": [
            "Actualizar WooCommerce Payments a ≥ 5.6.2",
            "WP-CLI: wp plugin update woocommerce-payments",
            "Auditar pedidos recientes por usuarios anómalos",
            "Revisar administradores creados: wp user list --role=administrator --orderby=registered",
        ],
        "urgency": "INMEDIATA — explotación activa ampliamente documentada",
    },
    "CVE-2020-35489": {
        "title":   "Subida de archivos sin restricción Contact Form 7",
        "steps": [
            "Actualizar Contact Form 7 a ≥ 5.3.2",
            "WP-CLI: wp plugin update contact-form-7",
            "Verificar wp-content/uploads/ por archivos .php, .phtml, .phar subidos",
            "Añadir regla nginx/Apache para denegar ejecución PHP en uploads",
        ],
        "urgency": "ALTA — permite subida y ejecución de webshell",
    },
}

_GENERIC_REMEDIATION = {
    "plugin_outdated": [
        "Actualizar desde Panel WP > Plugins > Actualizaciones disponibles",
        "Antes: hacer backup completo (DB + archivos)",
        "WP-CLI: wp plugin update {slug}",
        "Después: verificar funcionalidad crítica del sitio",
    ],
    "wordpress_outdated": [
        "Actualizar desde Panel WP > Escritorio > Actualizaciones",
        "Backup previo: wp db export && tar -czf backup-files.tar.gz wp-content/",
        "WP-CLI: wp core update",
        "WP-CLI: wp core update-db  (migrar base de datos si aplica)",
    ],
    "xmlrpc_enabled": [
        "Añadir en .htaccess (Apache): <Files xmlrpc.php>\\n  Order Deny,Allow\\n  Deny from all\\n</Files>",
        "Nginx: location = /xmlrpc.php { deny all; }",
        "O instalar plugin 'Disable XML-RPC' si no tienes acceso al servidor",
        "Verificar que Jetpack no dependa de XML-RPC antes de desactivarlo",
    ],
    "user_enumeration": [
        "Instalar plugin 'Stop User Enumeration' o añadir en functions.php:",
        "add_filter('redirect_canonical', function($r,$q){ if(is_author()) return false; return $r; }, 10, 2);",
        "En nginx: if ($args ~* ^author=) { return 403; }",
    ],
    "exposed_debug": [
        "En wp-config.php: define('WP_DEBUG', false);",
        "define('WP_DEBUG_LOG', false);",
        "define('WP_DEBUG_DISPLAY', false);",
        "Eliminar wp-content/debug.log si existe",
    ],
    "headers_missing": [
        "Añadir en .htaccess: Header always set X-Frame-Options DENY",
        "Header always set X-Content-Type-Options nosniff",
        "Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains'",
        "O usar plugin 'HTTP Headers' para gestión visual",
    ],
}


                                                                               
                                                     
                                                                               

def check_graphql_endpoint(
    session: "requests.Session",
    base_url: str,
    timeout: int = 8,
) -> dict:
    """
    Detecta endpoints GraphQL expuestos sin autenticación.
    WPGraphQL es uno de los plugins más populares para headless WP
    y ha tenido CVEs críticos (p.ej. CVE-2021-21389 — enumeración masiva).

    Retorna un dict con:
      - exposed:      bool
      - endpoint:     str | None
      - introspection: bool — si acepta queries de introspección
      - severity:     "critical" | "high" | "none"
      - issue:        str
    """
    result = {
        "exposed":       False,
        "endpoint":      None,
        "introspection": False,
        "severity":      "none",
        "issue":         "",
    }

    GRAPHQL_PATHS = [
        "/graphql",
        "/wp-json/wp/v2/graphql",
        "/?graphql",
        "/index.php?graphql",
    ]

    INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name}}}"}'

    for path in GRAPHQL_PATHS:
        url = urljoin(base_url, path)
        try:
                                
            r = session.get(url, timeout=timeout)
            if r.status_code in (200, 400):
                body = r.text[:500].lower()
                if "graphql" in body or "query" in body or "__schema" in body or "data" in body:
                    result["exposed"]  = True
                    result["endpoint"] = path
                    result["severity"] = "high"
                    result["issue"]    = f"GraphQL endpoint accesible en {path}"
                    break

                                                    
            r2 = session.post(
                url,
                data=INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            if r2.status_code == 200:
                try:
                    data = r2.json()
                    if "data" in data or "errors" in data:
                        result["exposed"]       = True
                        result["endpoint"]      = path
                        result["introspection"] = "__schema" in r2.text
                        result["severity"]      = "critical" if result["introspection"] else "high"
                        result["issue"]         = (
                            f"GraphQL con introspección habilitada en {path} — "
                            "esquema completo expuesto"
                            if result["introspection"] else
                            f"GraphQL endpoint accesible en {path}"
                        )
                        break
                except Exception:
                    pass
        except Exception as _e:
            log.debug("check_graphql_endpoint %s: %s", path, _e)

    return result


                                                                               
                                                       
                                                                               

def check_debug_log(
    session: "requests.Session",
    base_url: str,
    timeout: int = 8,
) -> dict:
    """
    Detecta el fichero de debug de WordPress expuesto públicamente.
    /wp-content/debug.log puede contener stack traces con rutas absolutas,
    versiones de PHP/WP exactas, credenciales en texto plano y queries SQL.

    Retorna un dict con:
      - exposed:   bool
      - url:       str | None
      - size_kb:   float | None
      - snippet:   str  — primeras 200 chars del log
      - severity:  "critical" | "high" | "none"
      - issue:     str
    """
    result = {
        "exposed":  False,
        "url":      None,
        "size_kb":  None,
        "snippet":  "",
        "severity": "none",
        "issue":    "",
    }

    DEBUG_PATHS = [
        "/wp-content/debug.log",
        "/wp-content/debug-bar.log",
        "/wp-content/logs/debug.log",
        "/debug.log",
    ]

    for path in DEBUG_PATHS:
        url = urljoin(base_url, path)
        try:
            r = session.get(url, timeout=timeout)
            if r.status_code != 200:
                continue

            text = r.text
            if not text or len(text) < 20:
                continue

                                           
            if any(sig in text[:300].lower() for sig in
                   ["404", "not found", "page not found", "no encontrada"]):
                continue

                                                 
            wp_log_signals = [
                "PHP Fatal error", "PHP Warning", "PHP Notice",
                "WordPress database error", "WP_DEBUG",
                "[", "Stack trace", "wp-content", "wp-includes",
            ]
            is_log = any(sig in text for sig in wp_log_signals)
            if not is_log:
                continue

            size_kb = len(r.content) / 1024
            snippet = text[:300].replace("\n", " | ")[:200]

                                                            
            has_creds = any(kw in text.lower() for kw in
                            ["password", "passwd", "secret", "token", "api_key", "DB_PASSWORD"])

            result.update({
                "exposed":  True,
                "url":      url,
                "size_kb":  round(size_kb, 1),
                "snippet":  snippet,
                "severity": "critical" if has_creds else "high",
                "issue":    (
                    f"debug.log expuesto ({size_kb:.1f} KB) con posibles credenciales"
                    if has_creds else
                    f"debug.log expuesto ({size_kb:.1f} KB) — stack traces y rutas del servidor visibles"
                ),
            })
            break

        except Exception as _e:
            log.debug("check_debug_log %s: %s", path, _e)

    return result


                                                                               
                                               
                                                                               

def check_jquery_version(
    session: "requests.Session",
    base_url: str,
    html: str,
    timeout: int = 8,
) -> dict:
    """
    Detecta versiones desactualizadas de jQuery cargadas en la página.
    WordPress incluye jQuery con cada versión del core; muchos sites
    usan versiones antiguas que tienen CVEs conocidos (XSS, prototipo).

    Retorna un dict con:
      - version:      str | None
      - url:          str | None
      - vulnerable:   bool
      - cves:         list[str]
      - severity:     "high" | "medium" | "low" | "none"
      - issue:        str
    """
    result = {
        "version":   None,
        "url":       None,
        "vulnerable": False,
        "cves":      [],
        "severity":  "none",
        "issue":     "",
    }

                                             
    VULNERABLE_VERSIONS = {
                                         
        "1.": ["CVE-2015-9251", "CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023"],
        "2.": ["CVE-2015-9251", "CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023"],
        "3.0": ["CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023"],
        "3.1": ["CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023"],
        "3.2": ["CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023"],
        "3.3": ["CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023"],
        "3.4": ["CVE-2020-11022", "CVE-2020-11023"],
        "3.5": ["CVE-2020-11022", "CVE-2020-11023"],
        "3.6": [],                                       
    }
    SAFE_FROM = (3, 6, 0)                               

    

                                        
                                       
    jquery_urls = re.findall(r'src=["\'"]([^"\']*jquery[^"\']*\.js[^"\'"]*)["\'"]', html, re.I)

    for jq_url in jquery_urls:
                                                
        m = re.search(r'jquery[.-](\d+\.\d+(?:\.\d+)?)', jq_url, re.I)
        if not m:
                                                                     
            full_url = jq_url if jq_url.startswith("http") else urljoin(base_url, jq_url)
            try:
                r = session.get(full_url, timeout=timeout)
                if r.status_code == 200:
                    bm = re.search(r'jQuery v(\d+\.\d+(?:\.\d+)?)', r.text[:500])
                    if bm:
                        m_ver = bm.group(1)
                    else:
                        continue
                else:
                    continue
            except Exception:
                continue
        else:
            m_ver = m.group(1)

        parts = [int(x) for x in (m_ver + ".0.0").split(".")[:3]]
        version_tuple = tuple(parts[:3])

        result["version"] = m_ver
        result["url"]     = jq_url

        if version_tuple < SAFE_FROM:
                                       
            cves = set()
            for prefix, cv in VULNERABLE_VERSIONS.items():
                if m_ver.startswith(prefix):
                    cves.update(cv)

            if cves:
                result.update({
                    "vulnerable": True,
                    "cves":       sorted(cves),
                    "severity":   "high" if version_tuple < (3, 0, 0) else "medium",
                    "issue":      (
                        f"jQuery {m_ver} desactualizado — "
                        f"vulnerable a {', '.join(sorted(cves)[:2])}"
                        + (" y más" if len(cves) > 2 else "")
                    ),
                })
            else:
                result.update({
                    "severity": "low",
                    "issue":    f"jQuery {m_ver} desactualizado (actualizar a 3.6+)",
                })
        break                                       

    return result

def get_remediation_steps(
    vuln_type: str,
    cve_id: str = "",
    plugin_slug: str = "",
    fixed_in: str = "",
    severity: str = "medium",
) -> dict:
    """
    Devuelve pasos de remediación concretos para una vulnerabilidad.
    Prioriza guías CVE-específicas; cae back a genéricas por tipo.
    """
    result = {
        "urgency":       "ESTA SEMANA" if severity in ("high", "critical") else "ESTE MES",
        "steps":         [],
        "wp_cli":        [],
        "config_snippet": None,
        "verification":  None,
    }

                       
    if cve_id and cve_id in _REMEDIATION_DETAIL:
        detail = _REMEDIATION_DETAIL[cve_id]
        result["steps"]   = detail["steps"]
        result["urgency"] = detail.get("urgency", result["urgency"])
        return result

                                  
    if fixed_in and plugin_slug:
        nice = plugin_slug.replace("-", " ").title()
        result["steps"] = [
            f"Actualizar {nice} a ≥ {fixed_in} desde Plugins > Actualizaciones",
            f"WP-CLI: wp plugin update {plugin_slug}",
            "Verificar funcionamiento tras la actualización",
            f"Confirmar versión: wp plugin get {plugin_slug} --field=version",
        ]
        result["wp_cli"] = [f"wp plugin update {plugin_slug}"]
        result["verification"] = f"wp plugin get {plugin_slug} --field=version  # debe ser ≥ {fixed_in}"
        if severity == "critical":
            result["urgency"] = "INMEDIATA — severidad crítica"
        return result

                       
    if vuln_type in ("wordpress", "core") or plugin_slug == "wordpress-core":
        result["steps"] = _GENERIC_REMEDIATION["wordpress_outdated"].copy()
        if fixed_in:
            result["steps"].insert(0, f"Actualizar WordPress Core a ≥ {fixed_in}")
        result["wp_cli"] = ["wp core update", "wp core update-db"]
        return result

                          
    result["steps"] = _GENERIC_REMEDIATION.get("plugin_outdated", [])
    if plugin_slug:
        result["steps"] = [s.replace("{slug}", plugin_slug) for s in result["steps"]]
    return result

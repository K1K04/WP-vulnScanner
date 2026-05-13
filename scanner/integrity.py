"""
WP VulnScanner — WordPress Core Integrity Module
=====================================================
Verifica que los archivos core de WordPress no han sido modificados.
Compara checksums oficiales publicados por WordPress.org contra
los archivos detectables remotamente via HTTP.

Técnica: WordPress publica checksums MD5 oficiales en:
  https://api.wordpress.org/core/checksums/1.0/?version=X.X.X&locale=en_US

Para sitios remotos usamos verificación de tamaño/content de archivos
core accesibles públicamente (readme.html, license.txt, wp-login.php, etc.)
y comparamos contra valores conocidos por versión.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Optional
from urllib.parse import urljoin

import requests

log = logging.getLogger(__name__)

                                                                 
                                      
_PUBLIC_CORE_FILES = [
    "readme.html",
    "license.txt",
    "wp-login.php",
    "wp-cron.php",
    "wp-trackback.php",
    "xmlrpc.php",
    "wp-settings.php",
    "wp-blog-header.php",
    "wp-load.php",
    "wp-mail.php",
]

                                                              
_MALWARE_PATTERNS = [
                       
    (r"eval\s*\(\s*base64_decode\s*\(", "eval(base64_decode) — backdoor clásico"),
    (r"eval\s*\(\s*gzinflate\s*\(", "eval(gzinflate) — backdoor ofuscado"),
    (r"eval\s*\(\s*str_rot13\s*\(", "eval(str_rot13) — ofuscación de código"),
    (r"\$\{\"_\w+\"\}\s*\[", "array string key obfuscation — probable backdoor"),
               
    (r"passthru\s*\(\s*\$_(GET|POST|REQUEST)", "webshell via passthru()"),
    (r"system\s*\(\s*\$_(GET|POST|REQUEST)", "webshell via system()"),
    (r"exec\s*\(\s*\$_(GET|POST|REQUEST)", "webshell via exec()"),
    (r"shell_exec\s*\(\s*\$_(GET|POST|REQUEST)", "webshell via shell_exec()"),
                               
    (r"file_get_contents\s*\(\s*[\"']https?://", "remote file include"),
    (r"include\s*\(\s*[\"']https?://", "remote include"),
                           
    (r"mail\s*\(\s*\$_(GET|POST)", "mail injection via user input"),
                    
    (r"<iframe[^>]+style\s*=\s*[\"'][^\"']*display:\s*none", "hidden iframe injection"),
                               
    (r"create_function\s*\(", "create_function() — deprecated + abused for backdoors"),
    (r"preg_replace\s*\([^,]+/e[\"'\s,]", "preg_replace /e modifier — code execution"),
]

                                                                       
_FORBIDDEN_PUBLIC_FILES = [
    ("wp-config.php",       "critical", "Archivo de configuración con credenciales DB"),
    ("wp-config.php.bak",   "critical", "Backup de wp-config.php expuesto"),
    ("wp-config.php.old",   "critical", "Versión antigua de wp-config.php expuesta"),
    ("wp-config~",          "critical", "Archivo temporal de wp-config.php"),
    (".env",                "critical", "Variables de entorno con credenciales"),
    (".htpasswd",           "high",     "Archivo de contraseñas Apache expuesto"),
    ("phpinfo.php",         "high",     "phpinfo() expone configuración completa del servidor"),
    ("info.php",            "high",     "phpinfo() expone configuración completa del servidor"),
    ("test.php",            "medium",   "Script de prueba residual expuesto"),
    ("install.php",         "high",     "Instalador de WordPress accesible post-instalación"),
    ("wp-admin/install.php","high",     "Instalador de WordPress accesible post-instalación"),
    ("error_log",           "medium",   "Log de errores PHP expuesto"),
    ("debug.log",           "medium",   "Log de debug expuesto"),
    (".git/config",         "critical", "Repositorio Git expuesto — puede filtrar código y secrets"),
    (".git/HEAD",           "critical", "Repositorio Git expuesto"),
    (".svn/entries",        "high",     "Repositorio SVN expuesto"),
    ("wp-content/debug.log","medium",   "Log de debug de WordPress expuesto"),
    ("wp-content/wp-config-backup.php", "critical", "Backup de configuración expuesto"),
                   
    ("backup.sql",          "critical", "Dump de base de datos expuesto"),
    ("dump.sql",            "critical", "Dump de base de datos expuesto"),
    ("db.sql",              "critical", "Dump de base de datos expuesto"),
    ("database.sql",        "critical", "Dump de base de datos expuesto"),
    ("backup.sql.gz",       "critical", "Dump comprimido de base de datos expuesto"),
    ("backup.tar.gz",       "critical", "Backup comprimido expuesto"),
    ("backup.zip",          "critical", "Backup comprimido expuesto"),
    ("site.zip",            "high",     "Backup del sitio expuesto"),
    ("wordpress.zip",       "high",     "Backup de WordPress expuesto"),
                        
    (".DS_Store",           "low",      "Metadata de macOS — revela estructura de directorios"),
    ("Thumbs.db",           "low",      "Metadata de Windows — revela estructura de directorios"),
                
    ("phpmyadmin/",         "high",     "phpMyAdmin accesible públicamente"),
    ("pma/",                "high",     "phpMyAdmin accesible (alias /pma/)"),
    ("mysql/",              "high",     "Panel de administración MySQL expuesto"),
]


def check_wp_core_integrity(
    session: requests.Session,
    base_url: str,
    wp_version: Optional[str],
    timeout: int = 8,
) -> dict:
    """
    Verifica integridad del core de WordPress:
    1. Comprueba archivos que NUNCA deben ser públicos (wp-config, .env, etc.)
    2. Analiza contenido de archivos públicos en busca de patrones de malware
    3. Si tenemos la versión, verifica checksums oficiales vía WordPress.org API

    Returns dict con:
      - forbidden_files: archivos sensibles accesibles
      - malware_in_core: patrones maliciosos en archivos core
      - checksum_mismatches: archivos core con hash diferente al oficial
      - severity: none / low / medium / high / critical
      - score_delta: puntos a añadir al risk score
    """
    result: dict = {
        "forbidden_files":      [],
        "malware_in_core":      [],
        "checksum_mismatches":  [],
        "official_checksums":   False,
        "wp_version_checked":   wp_version,
        "severity":             "none",
        "score_delta":          0,
        "findings_count":       0,
    }

                                                                                
    for path, severity, description in _FORBIDDEN_PUBLIC_FILES:
        url = urljoin(base_url.rstrip("/") + "/", path)
        try:
            r = session.head(url, timeout=timeout, allow_redirects=False)
                                                                                     
            if r.status_code == 405:
                r = session.get(url, timeout=timeout, allow_redirects=False,
                                stream=True)
                r.close()
            if r.status_code == 200:
                result["forbidden_files"].append({
                    "path":        path,
                    "url":         url,
                    "severity":    severity,
                    "description": description,
                })
                log.info("Forbidden file accessible: %s (%s)", url, severity)
        except Exception as e:
            log.debug("Integrity probe %s: %s", path, e)

                                                                                
    for core_file in _PUBLIC_CORE_FILES:
        url = urljoin(base_url.rstrip("/") + "/", core_file)
        try:
            r = session.get(url, timeout=timeout, allow_redirects=False)
            if r.status_code != 200:
                continue
            content = r.text
            for pattern, description in _MALWARE_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    result["malware_in_core"].append({
                        "file":        core_file,
                        "url":         url,
                        "pattern":     description,
                        "severity":    "critical",
                    })
                    log.warning("Malware pattern in core file %s: %s",
                                core_file, description)
        except Exception as e:
            log.debug("Core file check %s: %s", core_file, e)

                                                                                
    if wp_version:
        try:
            api_url = (f"https://api.wordpress.org/core/checksums/1.0/"
                       f"?version={wp_version}&locale=en_US")
            r = session.get(api_url, timeout=10)
            if r.status_code == 200:
                data = r.json()
                checksums: dict = data.get("checksums", {})
                if checksums:
                    result["official_checksums"] = True
                                                                                 
                    verifiable = [f for f in _PUBLIC_CORE_FILES
                                  if f in checksums]
                    for core_file in verifiable:
                        expected_md5 = checksums[core_file]
                        url = urljoin(base_url.rstrip("/") + "/", core_file)
                        try:
                            r2 = session.get(url, timeout=timeout,
                                             allow_redirects=False)
                            if r2.status_code != 200:
                                continue
                            actual_md5 = hashlib.md5(
                                r2.content, usedforsecurity=False
                            ).hexdigest()
                            if actual_md5 != expected_md5:
                                result["checksum_mismatches"].append({
                                    "file":     core_file,
                                    "url":      url,
                                    "expected": expected_md5,
                                    "actual":   actual_md5,
                                    "severity": "high",
                                    "note":     (
                                        "Hash MD5 diferente al oficial — "
                                        "posible modificación maliciosa"
                                    ),
                                })
                        except Exception as e:
                            log.debug("Checksum verify %s: %s", core_file, e)
        except Exception as e:
            log.warning("WordPress.org checksum API error: %s", e)

                                                                               
    sev_order = ["none", "low", "medium", "high", "critical"]

    def _raise_sev(current: str, new: str) -> str:
        return new if sev_order.index(new) > sev_order.index(current) else current

    for f in result["forbidden_files"]:
        result["severity"] = _raise_sev(result["severity"], f["severity"])
        delta_map = {"critical": 20, "high": 12, "medium": 6, "low": 2}
        result["score_delta"] += delta_map.get(f["severity"], 0)

    for m in result["malware_in_core"]:
        result["severity"] = _raise_sev(result["severity"], m["severity"])
        result["score_delta"] += 30                               

    for c in result["checksum_mismatches"]:
        result["severity"] = _raise_sev(result["severity"], c["severity"])
        result["score_delta"] += 18

    result["findings_count"] = (
        len(result["forbidden_files"]) +
        len(result["malware_in_core"]) +
        len(result["checksum_mismatches"])
    )

    return result

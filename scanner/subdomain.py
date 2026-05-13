"""
WP VulnScanner — Módulo de Enumeración de Subdominios v1.0
==============================================================
Mejora #6: Enumeración de subdominios y superficie de ataque.

Fuentes:
  - crt.sh (Certificate Transparency Logs) — gratuito, sin límite
  - DNS resolution para confirmar subdominios activos
  - Detección de WordPress en cada subdominio activo

Devuelve hasta MAX_SUBDOMAINS subdominios únicos con estado.
"""

from __future__ import annotations

import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutTimeout
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

import requests

log = logging.getLogger("wpvulnscan.subdomain")

MAX_SUBDOMAINS = 30
WP_INDICATORS  = ["/wp-content/", "/wp-includes/", "wp-login.php", "WordPress"]


                                                                               
                 
                                                                               

@dataclass
class SubdomainInfo:
    subdomain:    str
    ip:           Optional[str] = None
    alive:        bool = False
    uses_https:   bool = False
    is_wordpress: bool = False
    status_code:  Optional[int] = None
    server:       str = ""
    source:       str = "crt.sh"

    def to_dict(self) -> dict:
        return {
            "subdomain":    self.subdomain,
            "ip":           self.ip,
            "alive":        self.alive,
            "uses_https":   self.uses_https,
            "is_wordpress": self.is_wordpress,
            "status_code":  self.status_code,
            "server":       self.server,
            "source":       self.source,
        }


                                                                               
                                        
                                                                               

def fetch_crtsh(domain: str, timeout: int = 15) -> list[str]:
    """
    Consulta crt.sh para obtener subdominios del dominio desde certificados TLS.
    Devuelve lista de subdominios únicos (sin duplicados).
    """
    subdomains: set[str] = set()
    wildcard_re = re.compile(r"^\*\.")

    urls = [
        f"https://crt.sh/?q=%25.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json",
    ]
    transient_codes = {429, 500, 502, 503, 504}

    for url in urls:
        for _ in range(2):
            try:
                r = requests.get(
                    url,
                    timeout=timeout,
                    headers={
                        "Accept": "application/json",
                        "User-Agent": "WPVulnScannerPro/1.0 (subdomain-enum)",
                    },
                )

                if r.status_code in transient_codes:
                    log.debug("crt.sh temporal %s para %s", r.status_code, domain)
                    continue

                if r.status_code != 200:
                    log.debug("crt.sh status %s para %s", r.status_code, domain)
                    continue

                entries = r.json()
                if not isinstance(entries, list):
                    entries = []

                for entry in entries:
                                                                       
                    names = str(entry.get("name_value", "")).split("\n")
                    for name in names:
                        name = name.strip().lower()
                                           
                        name = wildcard_re.sub("", name)
                                                               
                        if name.endswith(f".{domain}") or name == domain:
                                                                      
                            if re.match(r"^[a-z0-9._-]+$", name):
                                subdomains.add(name)

                                                                                 
                if subdomains:
                    break

            except Exception as e:
                log.debug("crt.sh error para %s: %s", domain, e)

        if subdomains:
            break

    return sorted(subdomains)[:MAX_SUBDOMAINS * 2]                                     


                                                                               
                                          
                                                                               

def _resolve(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def _probe_subdomain(session: requests.Session, subdomain: str,
                     timeout: int = 8) -> SubdomainInfo:
    """Verifica si un subdominio está activo y detecta WordPress."""
    info = SubdomainInfo(subdomain=subdomain)
    info.ip = _resolve(subdomain)

    if not info.ip:
        return info                           

                                        
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True)
            info.alive       = True
            info.uses_https  = scheme == "https"
            info.status_code = r.status_code
            info.server      = r.headers.get("Server", "") or r.headers.get("server", "")

                                           
            body = r.text[:20000]
            info.is_wordpress = any(ind in body for ind in WP_INDICATORS)

            break                                    
        except requests.exceptions.SSLError:
                                                    
            continue
        except Exception:
            break

    return info


                                                                               
                       
                                                                               

def enumerate_subdomains(session: requests.Session, target_url: str,
                         timeout: int = 10) -> list[SubdomainInfo]:
    """
    Enumera subdominios del dominio objetivo usando crt.sh y los verifica.

    Devuelve lista de SubdomainInfo ordenada: activos primero, WordPress primero.
    """
    from urllib.parse import urlparse
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""

                                                                           
    import ipaddress
    try:
        ipaddress.ip_address(hostname)
        log.debug("Subdomain enum saltado: %s es una IP", hostname)
        return []
    except ValueError:
        pass                                    

                                                   
    parts = hostname.split(".")
    if len(parts) >= 2:
                                                                     
                                                                                      
        if len(parts) >= 3 and len(parts[-1]) == 2 and len(parts[-2]) <= 3:
            root_domain = ".".join(parts[-3:])
        else:
            root_domain = ".".join(parts[-2:])
    else:
        root_domain = hostname

    if not root_domain:
        return []

    log.info("Enumerando subdominios para: %s (desde crt.sh)", root_domain)

                                     
    candidates = fetch_crtsh(root_domain, timeout=15)
    log.info("crt.sh devolvió %d candidatos para %s", len(candidates), root_domain)

    if not candidates:
        return []

                                              
    candidates = candidates[:MAX_SUBDOMAINS]

                                          
    results: list[SubdomainInfo] = []

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {
            ex.submit(_probe_subdomain, session, sub, timeout): sub
            for sub in candidates
        }
        try:
            for future in as_completed(futures, timeout=30):
                try:
                    info = future.result()
                    results.append(info)
                except Exception:
                    pass
        except FutTimeout:
            log.warning("Timeout global en enumeración de subdominios")

                                                                      
    results.sort(key=lambda x: (not x.alive, not x.is_wordpress, x.subdomain))

    return results[:MAX_SUBDOMAINS]

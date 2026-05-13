"""
WP VulnScanner — Módulo de Reputación v1.0
================================================
Mejora #5: Check de reputación de IPs/dominio contra múltiples fuentes.

Fuentes gratuitas (sin clave):
  - URLhaus (abuse.ch) — malware URLs
  - PhishTank         — phishing

Fuentes con clave opcional (configurar en .env):
  - VirusTotal API    — análisis de URL/dominio
  - AbuseIPDB         — reputación de IP
  - Google Safe Browsing API — phishing/malware

Uso:
    from scanner.reputation import check_reputation
    result = check_reputation(session, "https://example.com", "1.2.3.4", config)
"""

from __future__ import annotations

import json
import logging
import os
import socket
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests

log = logging.getLogger("wpvulnscan.reputation")


                                                                               
                 
                                                                               

@dataclass
class ReputationResult:
    domain:              str = ""
    ip:                  str = ""
    clean:               bool = True                                                
    risk_level:          str = "clean"                                      
    threats:             list = field(default_factory=list)
    sources_checked:     list = field(default_factory=list)
    sources_flagged:     list = field(default_factory=list)
    virustotal_score:    Optional[str] = None                  
    virustotal_url:      Optional[str] = None
    abuseipdb_score:     Optional[int] = None          
    urlhaus_status:      str = ""
    gsb_threats:         list = field(default_factory=list)
    errors:              list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "domain":           self.domain,
            "ip":               self.ip,
            "clean":            self.clean,
            "risk_level":       self.risk_level,
            "threats":          self.threats,
            "sources_checked":  self.sources_checked,
            "sources_flagged":  self.sources_flagged,
            "virustotal_score": self.virustotal_score,
            "virustotal_url":   self.virustotal_url,
            "abuseipdb_score":  self.abuseipdb_score,
            "urlhaus_status":   self.urlhaus_status,
            "gsb_threats":      self.gsb_threats,
            "errors":           self.errors,
        }


                                                                               
         
                                                                               

def _resolve_ip(hostname: str) -> Optional[str]:
    """Resuelve el hostname a IP."""
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


                                                                               
                                             
                                                                               

def check_urlhaus(session: requests.Session, url: str, timeout: int = 10) -> dict:
    """
    Consulta URLhaus de abuse.ch.
    Devuelve {'status': 'online'/'offline'/'no_results'/'error', 'threat': str}
    """
    try:
        r = session.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=timeout,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if r.status_code == 200:
            data = r.json()
            query_status = data.get("query_status", "")
            if query_status == "no_results":
                return {"status": "clean", "threat": ""}
            elif query_status == "is_reporting_host":
                return {"status": "clean", "threat": ""}
            elif query_status in ("online", "offline"):
                threat = data.get("threat", "malware")
                tags    = data.get("tags") or []
                return {
                    "status": query_status,
                    "threat": threat,
                    "tags":   tags,
                    "urlhaus_reference": data.get("urlhaus_reference", ""),
                }
            return {"status": "clean", "threat": ""}
    except Exception as e:
        log.debug("URLhaus error: %s", e)
    return {"status": "error", "threat": ""}


                                                                               
                                             
                                                                               

def check_virustotal(session: requests.Session, url: str, api_key: str,
                     timeout: int = 15) -> dict:
    """
    Consulta VirusTotal URL scan.
    Devuelve {'positives': int, 'total': int, 'permalink': str, 'found': bool}
    """
    import base64
    try:
                                                              
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        r = session.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=timeout,
        )
        if r.status_code == 200:
            data = r.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0
            positives = malicious + suspicious
            return {
                "found":      True,
                "positives":  positives,
                "total":      total,
                "malicious":  malicious,
                "suspicious": suspicious,
                "permalink":  f"https://www.virustotal.com/gui/url/{url_id}",
                "categories": attrs.get("categories", {}),
            }
        elif r.status_code == 404:
            return {"found": False, "positives": 0, "total": 0}
        else:
            return {"found": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        log.debug("VirusTotal error: %s", e)
        return {"found": False, "error": str(e)}


                                                                               
                                                   
                                                                               

def check_abuseipdb(session: requests.Session, ip: str, api_key: str,
                    timeout: int = 10) -> dict:
    """
    Consulta AbuseIPDB para la IP.
    Devuelve {'abuse_confidence_score': int, 'total_reports': int, 'country': str}
    """
    try:
        r = session.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=timeout,
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            return {
                "found":                  True,
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports":          data.get("totalReports", 0),
                "country_code":           data.get("countryCode", ""),
                "isp":                    data.get("isp", ""),
                "domain":                 data.get("domain", ""),
                "is_whitelisted":         data.get("isWhitelisted", False),
                "usage_type":             data.get("usageType", ""),
            }
        return {"found": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        log.debug("AbuseIPDB error: %s", e)
        return {"found": False, "error": str(e)}


                                                                               
                                                        
                                                                               

def check_google_safe_browsing(session: requests.Session, url: str,
                                api_key: str, timeout: int = 10) -> list[str]:
    """
    Consulta Google Safe Browsing API v4.
    Devuelve lista de tipos de amenaza detectados.
    """
    try:
        body = {
            "client": {"clientId": "wpvulnscanner", "clientVersion": "5.0"},
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING",
                                     "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": url}],
            }
        }
        r = session.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=body,
            timeout=timeout,
        )
        if r.status_code == 200:
            matches = r.json().get("matches", [])
            return [m.get("threatType", "UNKNOWN") for m in matches]
    except Exception as e:
        log.debug("Google Safe Browsing error: %s", e)
    return []


                                                                               
                                    
                                                                               

def check_phishtank(session: requests.Session, url: str, timeout: int = 10) -> dict:
    """Consulta PhishTank para la URL."""
    try:
        r = session.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json"},
            timeout=timeout,
            headers={"User-Agent": "phishtank/WPVulnScanner"},
        )
        if r.status_code == 200:
            data = r.json().get("results", {})
            return {
                "in_database": data.get("in_database", False),
                "phish":       data.get("valid", False),
                "verified":    data.get("verified", False),
            }
    except Exception as e:
        log.debug("PhishTank error: %s", e)
    return {"in_database": False, "phish": False}


                                                                               
                       
                                                                               

def check_reputation(session: requests.Session, target_url: str,
                     timeout: int = 12) -> ReputationResult:
    """
    Ejecuta todas las verificaciones de reputación disponibles.
    Las claves API se leen de variables de entorno.
    """
    result = ReputationResult()

    parsed = urlparse(target_url)
    result.domain = parsed.hostname or ""

                 
    if result.domain:
        ip = _resolve_ip(result.domain)
        if ip:
            result.ip = ip

                           
    vt_key    = os.getenv("VT_API_KEY", "")
    abip_key  = os.getenv("ABUSEIPDB_API_KEY", "")
    gsb_key   = os.getenv("GSB_API_KEY", "")

                                                                                
    try:
        result.sources_checked.append("URLhaus")
        uh = check_urlhaus(session, target_url, timeout=timeout)
        status = uh.get("status", "clean")
        result.urlhaus_status = status
        if status in ("online", "offline") and uh.get("threat"):
            result.clean = False
            result.sources_flagged.append("URLhaus")
            threat_desc = f"URLhaus: {uh['threat']}"
            if uh.get("tags"):
                threat_desc += f" [{', '.join(uh['tags'])}]"
            result.threats.append(threat_desc)
            if uh.get("urlhaus_reference"):
                result.threats.append(f"Referencia: {uh['urlhaus_reference']}")
    except Exception as e:
        result.errors.append(f"URLhaus: {e}")

                                                                                
    if vt_key:
        try:
            result.sources_checked.append("VirusTotal")
            vt = check_virustotal(session, target_url, vt_key, timeout=timeout)
            if vt.get("found"):
                positives = vt.get("positives", 0)
                total     = vt.get("total", 0)
                result.virustotal_score = f"{positives}/{total}"
                result.virustotal_url   = vt.get("permalink", "")
                if positives > 0:
                    result.clean = False
                    result.sources_flagged.append("VirusTotal")
                    result.threats.append(
                        f"VirusTotal: {positives}/{total} motores detectan amenaza"
                    )
        except Exception as e:
            result.errors.append(f"VirusTotal: {e}")

                                                                                
    if abip_key and result.ip:
        try:
            result.sources_checked.append("AbuseIPDB")
            ab = check_abuseipdb(session, result.ip, abip_key, timeout=timeout)
            if ab.get("found"):
                score = ab.get("abuse_confidence_score", 0)
                result.abuseipdb_score = score
                if score >= 25:
                    result.clean = False
                    result.sources_flagged.append("AbuseIPDB")
                    result.threats.append(
                        f"AbuseIPDB: IP {result.ip} con score de abuso {score}/100 "
                        f"({ab.get('total_reports',0)} reportes en 90 días)"
                    )
        except Exception as e:
            result.errors.append(f"AbuseIPDB: {e}")

                                                                                
    if gsb_key:
        try:
            result.sources_checked.append("Google Safe Browsing")
            gsb_threats = check_google_safe_browsing(session, target_url, gsb_key, timeout=timeout)
            result.gsb_threats = gsb_threats
            if gsb_threats:
                result.clean = False
                result.sources_flagged.append("Google Safe Browsing")
                result.threats.append(
                    f"Google Safe Browsing: {', '.join(gsb_threats)}"
                )
        except Exception as e:
            result.errors.append(f"Google Safe Browsing: {e}")

                                                                                
                                                                           
                                                                       
    try:
        result.sources_checked.append("PhishTank")
        pt = check_phishtank(session, target_url, timeout=timeout)
        if pt.get("phish") and pt.get("verified"):
            result.clean = False
            result.sources_flagged.append("PhishTank")
            result.threats.append(
                f"PhishTank: URL reportada como phishing verificado: {target_url}"
            )
        elif pt.get("in_database") and not pt.get("phish"):
                                                                               
            pass
    except Exception as e:
        result.errors.append(f"PhishTank: {e}")

                                                                                
    flagged = len(result.sources_flagged)
    if flagged == 0:
        result.risk_level = "clean"
    elif flagged == 1:
        result.risk_level = "suspicious"
    else:
        result.risk_level = "malicious"

                                          
    if result.abuseipdb_score and result.abuseipdb_score >= 75:
        result.risk_level = "malicious"
        result.clean = False

    return result

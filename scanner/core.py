"""
WP VulnScanner — Motor de Escaneo v5.1
==========================================
Mejoras v5.1:
  - Detección de versión WP por hashes de assets públicos (#2)
  - Detección de malware en scripts JS externos cargados (#4)
  - Análisis de cabeceras de seguridad profundo: CSP, HSTS max-age, cookies (#7)
  - Detección mejorada de wp-cron y rutas sensibles (#8)
  - Fingerprinting de servidor/stack avanzado: PHP, servidor web, CDN (#9)
  - Risk score mejorado con CVSS temporal y exploit disponible (#10)
  - Integración de reputación y subdominios en ScanResult
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import socket
import ssl
import threading
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Callable
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

                                                                             
from scanner.utils import _version_lt, detect_waf_from_response

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("wpvulnscan.core")


                                                                               
                  
                                                                               

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

SEVERITY_ORDER = {
    Severity.CRITICAL: 0, Severity.HIGH: 1,
    Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4,
}


@dataclass
class PluginInfo:
    slug:           str
    version:        Optional[str]
    detected_via:   str
    confidence:     int
    latest_version: Optional[str] = None
    is_outdated:    bool = False
    type:           str = "plugin"

    def to_dict(self) -> dict:
        return {
            "slug": self.slug, "version": self.version,
            "detected_via": self.detected_via, "confidence": self.confidence,
            "latest_version": self.latest_version,
            "is_outdated": self.is_outdated, "type": self.type,
        }


@dataclass
class UserInfo:
    id:           int
    login:        Optional[str]
    display_name: Optional[str]
    source:       str

    def to_dict(self) -> dict:
        return {"id": self.id, "login": self.login,
                "display_name": self.display_name, "source": self.source}


@dataclass
class ExposedFile:
    path:        str
    url:         str
    description: str
    severity:    str = "high"
    extra:       str = ""

    def to_dict(self) -> dict:
        return {"path": self.path, "url": self.url,
                "description": self.description,
                "severity": self.severity, "extra": self.extra}


@dataclass
class Vulnerability:
    plugin_slug:        str
    plugin_version:     Optional[str]
    cve_id:             Optional[str]
    title:              str
    severity:           Severity
    cvss_score:         Optional[float]
    fixed_in:           Optional[str]
    references:         list[str] = field(default_factory=list)
    description:        str = ""
    type:               str = "plugin"
    recommended_action: str = ""                                               
    source:             str = "offline"                                        
    cvss_vector:        Optional[str]   = None                      
    epss:               Optional[float] = None            
    kev:                bool            = False                    
    version_unconfirmed: bool           = False                         

    def _build_recommended_action(self) -> str:
        """Genera automáticamente la acción recomendada con pasos concretos y WP-CLI."""
        if self.recommended_action:
            return self.recommended_action
        try:
            from scanner.new_detections import get_remediation_steps
            rem = get_remediation_steps(
                vuln_type  = self.type,
                cve_id     = self.cve_id or "",
                plugin_slug= self.plugin_slug or "",
                fixed_in   = self.fixed_in or "",
                severity   = self.severity.value if hasattr(self.severity, "value") else str(self.severity),
            )
            steps = rem.get("steps", [])
            if steps:
                urgency = rem.get("urgency", "")
                header = f"[{urgency}] " if urgency else ""
                return header + " → ".join(steps[:3])
        except Exception as _e:
            try:
                log.debug("_build_recommended_action suppressed: %s", _e)
            except Exception:
                pass
                           
        if self.fixed_in:
            component = self.plugin_slug.replace("-", " ").title()
            return (f"Actualizar {component} a ≥ {self.fixed_in}: "
                    f"wp plugin update {self.plugin_slug}")
        if self.type == "wordpress":
            return "wp core update && wp core update-db"
        return f"Desactivar '{self.plugin_slug}' hasta que el proveedor publique parche: wp plugin deactivate {self.plugin_slug}"

    def to_dict(self) -> dict:
        action = self._build_recommended_action()
        return {
            "plugin_slug": self.plugin_slug, "plugin_version": self.plugin_version,
            "cve_id": self.cve_id, "title": self.title,
            "severity": self.severity.value, "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "fixed_in": self.fixed_in, "references": self.references,
            "description": self.description, "type": self.type,
            "recommended_action": action,
            "source": self.source,
            "epss": self.epss,
            "kev": self.kev,
            "version_unconfirmed": self.version_unconfirmed,
        }


@dataclass
class SSLInfo:
    valid:     bool = False
    expired:   bool = False
    days_left: Optional[int] = None
    issuer:    str = ""
    subject:   str = ""
    error:     str = ""

    def to_dict(self) -> dict:
        return vars(self)


@dataclass
class ScanResult:
    target_url:         str
    scan_id:            str
    started_at:         float
    finished_at:        Optional[float]     = None
    wp_version:         Optional[str]       = None
    wp_version_source:  str                 = ""
    wp_latest_version:  Optional[str]       = None
    wp_outdated:        bool                = False
    plugins:            list[PluginInfo]    = field(default_factory=list)
    themes:             list[PluginInfo]    = field(default_factory=list)
    vulnerabilities:    list[Vulnerability] = field(default_factory=list)
    exposed_files:      list[ExposedFile]   = field(default_factory=list)
    headers_issues:     list[str]           = field(default_factory=list)
    headers_ok:         list[str]           = field(default_factory=list)
    users:              list[UserInfo]      = field(default_factory=list)
    malware_indicators: list[str]           = field(default_factory=list)
    ssl_info:           Optional[SSLInfo]   = None
    is_wordpress:       bool                = False
    server_info:        str                 = ""
    cms_info:           str                 = ""
    php_version:        Optional[str]       = None
    xmlrpc_enabled:     bool                = False
    login_exposed:      bool                = False
    wpscan_api_used:    bool                = False
    wpscan_api_error:   str                 = ""
    db_days_old:        int                 = 0
    db_last_update:     str                 = ""
    waf_detected:       list[str]           = field(default_factory=list)
    errors:             list[str]           = field(default_factory=list)
                                                                                
    reputation:         Optional[dict]      = None
    subdomains:         list[dict]          = field(default_factory=list)
    js_threats:         list[str]           = field(default_factory=list)
    csp_analysis:       dict                = field(default_factory=dict)
    hsts_analysis:      dict                = field(default_factory=dict)
    cookie_issues:      list[str]           = field(default_factory=list)
    server_stack:       dict                = field(default_factory=dict)
    wp_version_hashes:  Optional[str]       = None
    exploit_available:  list[str]           = field(default_factory=list)
                                                                                
    robots_analysis:    dict                = field(default_factory=dict)
    admin_protection:   dict                = field(default_factory=dict)
                                                                               
    cors_issues:        dict                = field(default_factory=dict)
    debug_mode:         dict                = field(default_factory=dict)
    tls_analysis:       dict                = field(default_factory=dict)
    custom_login:       dict                = field(default_factory=dict)
    wp_cron_abuse:      dict                = field(default_factory=dict)
    multisite_info:     dict                = field(default_factory=dict)
    rest_api_issues:    dict                = field(default_factory=dict)
    redirect_chain:     dict                = field(default_factory=dict)
    timing_plugins:     list[dict]          = field(default_factory=list)
    post_injections:    list[dict]          = field(default_factory=list)
                                                                               
    core_integrity:     dict                = field(default_factory=dict)
    backup_files:       dict                = field(default_factory=dict)
    js_analysis:        dict                = field(default_factory=dict)
    users_advanced:     dict                = field(default_factory=dict)
    login_protection:   dict                = field(default_factory=dict)
                                                                               
    deep_scan:          dict                = field(default_factory=dict)
                                                                                
    threat_intel:       dict                = field(default_factory=dict)                   
    compliance:         dict                = field(default_factory=dict)                           
                                                                                
    passive_fingerprints: dict             = field(default_factory=dict)
    exposed_emails:     list               = field(default_factory=list)
    pingback_url:       str                = ""
                                                                               
    recon:              dict               = field(default_factory=dict)

    @property
    def risk_score(self) -> int:
        """
        Score de riesgo v5.7 — algoritmo con caps por categoría.

        FIX-4: El multiplicador de severidad ahora distingue si existe fix publicado:
          - Sin fix conocido (fixed_in=None): multiplicador +30% adicional
            (riesgo mayor porque no hay parche disponible).
          - Fix publicado hace >90 días: multiplicador -20%
            (el sitio debería haber actualizado ya, pero no es urgencia zero-day).
          - Fix reciente (<90 días): sin cambio (urgencia normal).

        Distribución de 100 puntos:
          Vulnerabilidades  → máx 50  (peso principal)
          Archivos expuestos→ máx 15
          Configuración     → máx 15  (headers, CSP, TLS, etc.)
          Exposición/Infra  → máx 12  (usuarios, XML-RPC, login, etc.)
          Reputación/Malware→ máx 8   (listas negras, JS malicioso)
        """
        import datetime as _dt

                                                                               
        vuln_score = 0
        SEV_WEIGHT = {Severity.CRITICAL: 25, Severity.HIGH: 10,
                      Severity.MEDIUM:   3,  Severity.LOW:   1, Severity.INFO: 0}
        for v in self.vulnerabilities:
            base = SEV_WEIGHT.get(v.severity, 0)
            cvss = float(v.cvss_score or 0)

                                                                     
            if v.cve_id and v.cve_id in self.exploit_available:
                base = int(base * 1.6)                         
            elif cvss >= 9.5:
                base = int(base * 1.4)
            elif cvss >= 7.0:
                base = int(base * 1.2)

                                                     
            fixed_in = getattr(v, "fixed_in", None) or ""
            if not fixed_in:
                                                   
                base = int(base * 1.3)
            else:
                                                                             
                                                                                         
                updated = getattr(v, "updated_at", None) or ""
                if updated:
                    try:
                        fix_date = _dt.datetime.fromisoformat(updated[:10])
                        days_since = (_dt.datetime.now() - fix_date).days
                        if days_since > 90:
                            base = int(base * 0.85)                   
                    except Exception as _e:
                        log.debug("suppressed: %s", _e)

            vuln_score += base
        vuln_score = min(vuln_score, 50)

                                                                               
        FILE_SEV = {"critical": 8, "high": 4, "medium": 2, "low": 1, "info": 0}
        file_score = sum(FILE_SEV.get(f.severity, 2) for f in self.exposed_files)
        file_score = min(file_score, 15)

                                                                               
        cfg_score = 0
                                                                  
        cfg_score += min(len(self.headers_issues) * 1.5, 7)
                          
        if self.csp_analysis.get("unsafe_inline"): cfg_score += 2
        if self.csp_analysis.get("unsafe_eval"):   cfg_score += 2
        if not self.csp_analysis.get("present"):   cfg_score += 1
                      
        if not self.hsts_analysis.get("present"):  cfg_score += 1
             
        if self.tls_analysis.get("deprecated_protocol"): cfg_score += 4
        if self.tls_analysis.get("weak_cipher"):          cfg_score += 2
                              
        if self.cors_issues.get("vulnerable"):
            cfg_score += {"critical": 6, "high": 4, "medium": 2}.get(
                self.cors_issues.get("severity", "medium"), 1)
                             
        if self.debug_mode.get("debug_active"): cfg_score += 5
                                         
        if self.rest_api_issues.get("allows_edit_context"):   cfg_score += 5
        elif self.rest_api_issues.get("exposes_private_posts"): cfg_score += 3
        elif self.rest_api_issues.get("exposes_emails"):       cfg_score += 2
                           
        if self.wp_outdated: cfg_score += 4
                                 
        if self.ssl_info and (self.ssl_info.expired or not self.ssl_info.valid):
            cfg_score += 6
                           
        cfg_score += min(len(self.cookie_issues) * 1, 3)
                                 
        if self.robots_analysis.get("allowed_sensitive"):
            cfg_score += min(len(self.robots_analysis["allowed_sensitive"]) * 2, 4)
        cfg_score = min(int(cfg_score), 15)

                                                                               
        infra_score = 0
        if self.redirect_chain.get("suspicious"):  infra_score += 8                   
        if self.xmlrpc_enabled:                    infra_score += 3
        if self.login_exposed:                     infra_score += 2
        if self.wp_cron_abuse.get("abusable"):     infra_score += 2
                              
        infra_score += min(len(self.users) * 2, 4)
                                       
        ap = self.admin_protection
        if ap.get("accessible") and not ap.get("basic_auth_required") and not ap.get("forbidden"):
            if not ap.get("has_captcha") and not ap.get("login_form_hardened"):
                infra_score += 3
                   
        if self.deep_scan:
            login_ds = self.deep_scan.get("login_security", {})
            if login_ds.get("username_enumerable"):                    infra_score += 2
            if not login_ds.get("rate_limit_detected") and login_ds.get("login_accessible"):
                infra_score += 3
            ping = self.deep_scan.get("pingback", {})
            if ping.get("ssrf_risk"):                                  infra_score += 4
            woo  = self.deep_scan.get("woocommerce", {})
            if woo.get("api_accessible"):                              infra_score += 3
            rest_ds = self.deep_scan.get("rest_deep", {})
            for route in rest_ds.get("exposed_routes", []):
                sev = route.get("severity", "medium")
                infra_score += {"critical": 4, "high": 2, "medium": 1, "low": 0}.get(sev, 0)
            uploads = self.deep_scan.get("uploads", {})
            for f in uploads.get("dangerous_files", []):
                sev = f.get("severity", "medium")
                infra_score += {"critical": 5, "high": 2, "medium": 1}.get(sev, 0)
        infra_score = min(int(infra_score), 12)

                                                                               
        rep_score = 0
        if self.reputation:
            risk_lvl = self.reputation.get("risk_level", "clean")
            if risk_lvl == "malicious":    rep_score += 8
            elif risk_lvl == "suspicious": rep_score += 4
        rep_score += min(len(self.malware_indicators) * 3, 6)
        rep_score += min(len(self.js_threats) * 2, 4)
        rep_score += min(len(self.post_injections) * 3, 6)
        rep_score = min(int(rep_score), 8)

        total = vuln_score + file_score + cfg_score + infra_score + rep_score
        return min(total, 100)

    @property
    def risk_label(self) -> str:
        s = self.risk_score
        if s >= 70: return "CRÍTICO"
        if s >= 45: return "ALTO"
        if s >= 20: return "MEDIO"
        return "BAJO"

    @property
    def risk_color(self) -> str:
        s = self.risk_score
        if s >= 70: return "#ff4757"
        if s >= 45: return "#ff6b35"
        if s >= 20: return "#ffa502"
        return "#2ed573"

    @property
    def duration(self) -> float:
        return round(self.finished_at - self.started_at, 2) if self.finished_at else 0.0

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url, "scan_id": self.scan_id,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "duration": self.duration, "is_wordpress": self.is_wordpress,
            "cms_info": self.cms_info, "wp_version": self.wp_version,
            "wp_version_source": self.wp_version_source,
            "wp_latest_version": self.wp_latest_version,
            "wp_outdated": self.wp_outdated, "server_info": self.server_info,
            "php_version": self.php_version, "xmlrpc_enabled": self.xmlrpc_enabled,
            "login_exposed": self.login_exposed, "wpscan_api_used": self.wpscan_api_used,
            "wpscan_api_error": self.wpscan_api_error,
            "db_days_old": self.db_days_old, "db_last_update": self.db_last_update,
            "waf_detected": self.waf_detected,
            "risk_score": self.risk_score, "risk_label": self.risk_label,
            "risk_color": self.risk_color,
            "plugins": [p.to_dict() for p in self.plugins],
            "themes":  [t.to_dict() for t in self.themes],
            "vulnerabilities":  getattr(self, "_enriched_vulns", None) or [v.to_dict() for v in self.vulnerabilities],
            "exposed_files":    [f.to_dict() for f in self.exposed_files],
            "headers_issues":   self.headers_issues,
            "headers_ok":       self.headers_ok,
            "users":            [u.to_dict() for u in self.users],
            "malware_indicators": self.malware_indicators,
            "ssl_info":         self.ssl_info.to_dict() if self.ssl_info else None,
            "errors":           self.errors,
            "reputation":        self.reputation,
            "subdomains":        self.subdomains,
            "js_threats":        self.js_threats,
            "csp_analysis":      self.csp_analysis,
            "hsts_analysis":     self.hsts_analysis,
            "cookie_issues":     self.cookie_issues,
            "server_stack":      self.server_stack,
            "wp_version_hashes": self.wp_version_hashes,
            "exploit_available": self.exploit_available,
            "robots_analysis":   self.robots_analysis,
            "admin_protection":  self.admin_protection,
                                 
            "cors_issues":       self.cors_issues,
            "debug_mode":        self.debug_mode,
            "tls_analysis":      self.tls_analysis,
            "custom_login":      self.custom_login,
            "wp_cron_abuse":     self.wp_cron_abuse,
            "multisite_info":    self.multisite_info,
            "rest_api_issues":   self.rest_api_issues,
            "redirect_chain":    self.redirect_chain,
            "timing_plugins":    self.timing_plugins,
            "post_injections":   self.post_injections,
                    
            "core_integrity":    self.core_integrity,
            "backup_files":      self.backup_files,
            "js_analysis":       self.js_analysis,
            "users_advanced":    self.users_advanced,
            "login_protection":  getattr(self, "login_protection", {}),
                            
            "deep_scan":         self.deep_scan,
                                            
            "threat_intel":      self.threat_intel,
            "compliance":        self.compliance,
            "passive_fingerprints": self.passive_fingerprints,
            "exposed_emails":    self.exposed_emails,
            "pingback_url":      self.pingback_url,
                                
            "recon":             self.recon,
            "summary": {
                "plugins_found":    len(self.plugins),
                "themes_found":     len(self.themes),
                "vulns_found":      len(self.vulnerabilities),
                "critical_vulns":   sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL),
                "high_vulns":       sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH),
                "medium_vulns":     sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM),
                "exposed_files":    len(self.exposed_files),
                "header_issues":    len(self.headers_issues),
                "users_found":      len(self.users),
                "malware_found":    len(self.malware_indicators),
                "outdated_plugins": sum(1 for p in self.plugins if p.is_outdated),
                "outdated_themes":  sum(1 for t in self.themes if t.is_outdated),
                "wpscan_api_used":  self.wpscan_api_used,
            }
        }


                                                                               
               
                                                                               

@dataclass
class ScannerConfig:
    timeout:          int  = 12
    max_workers:      int  = 3
    request_delay:    float = 0.5                                            
    verify_ssl:       bool = False
    wpscan_api_token: Optional[str] = None
    check_wp_org:     bool = True
                                                                       
    user_agent: Optional[str] = None
                                                                                  
                                                                                    
    module_cache_ttl: int  = 0
                                                                                   
    run_recon:        bool = True
    run_nmap:         bool = True
    run_nikto:        bool = False
    force_generic_passive: bool = True

    def __post_init__(self) -> None:
        if not self.user_agent:
            self.user_agent = (
                os.environ.get("SCANNER_USER_AGENT", "").strip()
                or os.environ.get("USER_AGENT", "").strip()
                or _UA_POOL[0]
            )

    def get_user_agent(self) -> str:
        if self.user_agent:
            return self.user_agent
        return _UA_POOL[0]


                                                                           
_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
]


                                                                               
              
                                                                               

class HostCircuitBreaker:
    """
    Circuit breaker por host. Después de THRESHOLD fallos de conexión
    consecutivos abre el circuito y rechaza peticiones sin intentarlas.
    Se reinicia automáticamente tras RESET_AFTER segundos (por si el host vuelve).
    """
    THRESHOLD   = 8                                               
    RESET_AFTER = 30                                         

    def __init__(self):
        self._lock          = threading.Lock()
        self._fail_count: dict[str, int]   = {}
        self._open_since: dict[str, float] = {}

    def record_failure(self, host: str) -> None:
        with self._lock:
            self._fail_count[host] = self._fail_count.get(host, 0) + 1
            if self._fail_count[host] >= self.THRESHOLD:
                if host not in self._open_since:
                    log.warning("CircuitBreaker: circuito abierto para %s (%d fallos)",
                                host, self._fail_count[host])
                self._open_since[host] = time.time()

    def record_success(self, host: str) -> None:
        with self._lock:
            self._fail_count.pop(host, None)
            self._open_since.pop(host, None)

    def is_open(self, host: str) -> bool:
        with self._lock:
            since = self._open_since.get(host)
            if since is None:
                return False
            if time.time() - since > self.RESET_AFTER:
                                                                                
                self._open_since.pop(host, None)
                self._fail_count[host] = 0
                return False
            return True


                                                              
_circuit_breaker = HostCircuitBreaker()


class ServiceCircuitBreaker:
    """Circuit breaker genérico para servicios externos (APIs, Shodan, WPScan, etc.).

    Uso:
        _cb = ServiceCircuitBreaker("wpscan-api", threshold=5, reset_after=60)

        def call_wpscan():
            if _cb.is_open():
                raise RuntimeError("WPScan API circuit open")
            try:
                result = requests.get(...)
                _cb.record_success()
                return result
            except Exception as e:
                _cb.record_failure()
                raise
    """
    def __init__(self, name: str, threshold: int = 5, reset_after: int = 60):
        self.name        = name
        self.threshold   = threshold
        self.reset_after = reset_after
        self._lock       = threading.Lock()
        self._failures   = 0
        self._open_since: float | None = None

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.threshold:
                if self._open_since is None:
                    log.warning("ServiceCircuitBreaker[%s]: circuito abierto (%d fallos)",
                                self.name, self._failures)
                self._open_since = time.time()

    def record_success(self) -> None:
        with self._lock:
            if self._failures > 0:
                log.info("ServiceCircuitBreaker[%s]: circuito cerrado", self.name)
            self._failures   = 0
            self._open_since = None

    def is_open(self) -> bool:
        with self._lock:
            if self._open_since is None:
                return False
            if time.time() - self._open_since > self.reset_after:
                                                
                self._open_since = None
                self._failures   = 0
                return False
            return True

    def call(self, fn: Callable, *args, **kwargs):
        """Ejecuta fn(*args, **kwargs) con circuit-breaker automático."""
        if self.is_open():
            raise RuntimeError(f"ServiceCircuitBreaker[{self.name}] abierto — omitiendo llamada")
        try:
            result = fn(*args, **kwargs)
            self.record_success()
            return result
        except Exception:
            self.record_failure()
            raise


                                    
_cb_wpscan  = ServiceCircuitBreaker("wpscan-api",  threshold=5, reset_after=120)
_cb_shodan  = ServiceCircuitBreaker("shodan",       threshold=3, reset_after=180)
_cb_nvd     = ServiceCircuitBreaker("nvd-api",      threshold=4, reset_after=300)


                                                                               
                                               
                                                                               

class _ModuleCache:
    """Cache en memoria de resultados parciales de escaneo por (url, módulo).

    Permite que un re-scan del mismo target dentro del TTL reutilice resultados
    de módulos costosos (plugins, themes, vulns) sin repetir peticiones HTTP.
    """
    def __init__(self) -> None:
        self._lock  = threading.Lock()
        self._store: dict[tuple[str, str], tuple[float, object]] = {}

    def get(self, url: str, module: str, ttl: int) -> object | None:
        if ttl <= 0:
            return None
        key = (url, module)
        with self._lock:
            entry = self._store.get(key)
        if entry and (time.time() - entry[0]) < ttl:
            log.debug("ModuleCache hit: %s/%s", module, url)
            return entry[1]
        return None

    def set(self, url: str, module: str, value: object) -> None:
        key = (url, module)
        with self._lock:
            self._store[key] = (time.time(), value)
                                                                     
            if len(self._store) > 500:
                oldest = sorted(self._store.items(), key=lambda x: x[1][0])[:100]
                for k, _ in oldest:
                    del self._store[k]

    def invalidate(self, url: str) -> None:
        """Invalida todas las entradas de un URL (ej: al pedir re-scan forzado)."""
        with self._lock:
            keys = [k for k in self._store if k[0] == url]
            for k in keys:
                del self._store[k]


_module_cache = _ModuleCache()


                                                                               
                                                                    
                                                                               

class _AdaptiveHTTPAdapter(HTTPAdapter):
    """HTTPAdapter que detecta 429/503 y aplica backoff exponencial automático.

    Cuando el servidor responde con 429 (Too Many Requests) o 503 con
    Retry-After, el adapter duerme el tiempo indicado (o un mínimo de
    `_base_delay` segundos) antes de devolver la respuesta al caller.
    Esto evita que el scanner quede bloqueado en bucles de peticiones
    rechazadas, sin necesidad de Retry() global que duplica tiempos de espera.
    """
    _base_delay  = 2.0                                             
    _max_delay   = 60.0                     

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._backoff: dict[str, float] = {}                        
        self._lock = threading.Lock()

    def send(self, request, **kwargs):
        resp = super().send(request, **kwargs)
        host = request.url.split("/")[2] if "/" in request.url else request.url

        if resp.status_code in (429, 503):
            retry_after = resp.headers.get("Retry-After", "")
            try:
                delay = max(float(retry_after), self._base_delay)
            except (ValueError, TypeError):
                with self._lock:
                    prev = self._backoff.get(host, self._base_delay / 2)
                    delay = min(prev * 2, self._max_delay)
                    self._backoff[host] = delay

            log.warning("AdaptiveHTTPAdapter: %d recibido de %s — backoff %.1fs",
                        resp.status_code, host, delay)
            time.sleep(delay)
        else:
                                              
            with self._lock:
                self._backoff.pop(host, None)

        return resp


def _make_session(config: ScannerConfig) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": config.get_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
    })
    session.verify = config.verify_ssl
    retry = Retry(
        total=0,                                  
        connect=0,                                                                     
        read=False,
        status=0,
        raise_on_status=False,
    )
    adapter = _AdaptiveHTTPAdapter(
        max_retries=retry,
        pool_connections=10,
        pool_maxsize=20,
        pool_block=False,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


                                                                               
                                                                          
                                                                               


                                                                               
                             
                                                                               

WP_VERSION_PATTERNS = [
    (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([0-9.]+)', re.I), "meta-generator"),
    (re.compile(r'content=["\']WordPress\s+([0-9.]+)["\']', re.I),                                   "meta-alt"),
    (re.compile(r'<generator>https://wordpress\.org/\?v=([0-9.]+)</generator>', re.I),                "rss-generator"),
    (re.compile(r'wp-emoji-release\.min\.js\?ver=([0-9.]+)', re.I),                                   "emoji-asset"),
    (re.compile(r'wp-includes/css/dashicons\.min\.css\?ver=([0-9.]+)', re.I),                         "dashicons"),
    (re.compile(r'wp-includes/js/wp-embed\.min\.js\?ver=([0-9.]+)', re.I),                           "wp-embed"),
    (re.compile(r'/wp-includes/[^"\'?]+\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b', re.I),               "wp-includes"),
]
WP_INDICATORS = [
    r'/wp-content/', r'/wp-includes/', r'wp-json', r'xmlrpc\.php',
    r'wordpress', r'wp-login\.php',
]
PHP_VER_PATTERN = re.compile(r'PHP/([0-9]+\.[0-9]+\.[0-9]+)', re.I)


def _quick_wp_fingerprint(headers: dict, html_start: str) -> bool:
    """Fingerprint pasivo y rápido de WordPress a partir de cabeceras HTTP y
    los primeros 8KB del HTML. Se ejecuta ANTES de cualquier petición activa
    para evitar módulos costosos en sitios que claramente no son WordPress.

    Retorna True si hay evidencia suficiente de WordPress.
    Falsos negativos posibles (WP muy oculto), pero los falsos positivos son
    prácticamente nulos porque comprobamos señales independientes.
    """
    hl = {k.lower(): v for k, v in headers.items()}

                                   
    if "wordpress" in hl.get("x-generator", "").lower():
        return True

                                                 
    link_header = hl.get("link", "")
    if "wp-json" in link_header or "wp/v2" in link_header:
        return True

                                  
    set_cookie = hl.get("set-cookie", "")
    if "wordpress_test_cookie" in set_cookie or "wp-settings-" in set_cookie:
        return True

                                                    
    chunk = html_start[:8192]
    if "/wp-content/" in chunk or "/wp-includes/" in chunk:
        return True

                             
    if re.search(r'<meta[^>]+content=["\']WordPress', chunk, re.I):
        return True

    return False


def detect_wordpress(html: str, headers: dict) -> tuple[bool, Optional[str], str, Optional[str]]:
    combined = html[:80000]
    is_wp = any(re.search(p, combined, re.I) for p in WP_INDICATORS)
    if not is_wp:
        is_wp = "wordpress" in str(headers).lower()

    php_version = None
    powered_by = headers.get("X-Powered-By", "") or headers.get("x-powered-by", "")
    m = PHP_VER_PATTERN.search(powered_by)
    if m:
        php_version = m.group(1)

    for pattern, source in WP_VERSION_PATTERNS:
        m = pattern.search(combined)
        if m:
            return True, m.group(1), source, php_version

    return is_wp, None, "", php_version


def fetch_extra_sources(session, base_url: str, config: ScannerConfig) -> tuple[Optional[str], Optional[str]]:
         
    try:
        r = session.get(urljoin(base_url, "/?feed=rss2"), timeout=config.timeout)
        if r.status_code == 200:
            m = re.search(r'<generator>https://wordpress\.org/\?v=([0-9.]+)</generator>', r.text, re.I)
            if m:
                return m.group(1), "rss-feed"
    except Exception as _e:
        log.debug("core: %s", _e)
              
    try:
        r = session.get(urljoin(base_url, "/wp-json/"), timeout=config.timeout)
        if r.status_code == 200:
            data = r.json()
            ver = data.get("generator", "")
            m = re.search(r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)', ver)
            if m:
                return m.group(1), "rest-api"
    except Exception as _e:
        log.debug("core: %s", _e)
    return None, None


def get_wp_latest_version(session, config: ScannerConfig) -> Optional[str]:
    try:
        r = session.get("https://api.wordpress.org/core/version-check/1.7/", timeout=config.timeout)
        if r.status_code == 200:
            offers = r.json().get("offers", [])
            for offer in offers:
                if offer.get("response") == "upgrade":
                    return offer.get("version")
            if offers:
                return offers[0].get("version") or offers[0].get("current")
    except Exception as _e:
        log.debug("core: %s", _e)
    return None


                                                                               
            
                                                                               

PLUGIN_ASSET_RE = re.compile(r'/wp-content/plugins/([a-z0-9_-]+)/[^"\'<>\s]*\?ver=([0-9][0-9a-zA-Z._-]*)', re.I)
PLUGIN_SLUG_RE  = re.compile(r'/wp-content/plugins/([a-z0-9_-]+)/', re.I)
WPO_SLUG_RE     = re.compile(r'"slug"\s*:\s*"([a-z0-9_-]+)"', re.I)


def detect_plugins_from_html(html: str) -> dict[str, PluginInfo]:
    found: dict[str, PluginInfo] = {}
    for m in PLUGIN_ASSET_RE.finditer(html):
        slug, ver = m.group(1), m.group(2)
        if slug not in found:
            found[slug] = PluginInfo(slug=slug, version=ver, detected_via="html-asset", confidence=93)
    for m in PLUGIN_SLUG_RE.finditer(html):
        slug = m.group(1)
        if slug not in found:
            found[slug] = PluginInfo(slug=slug, version=None, detected_via="html-path", confidence=76)
    return found


def detect_plugins_from_rest_api(session, base_url: str, config: ScannerConfig) -> dict[str, PluginInfo]:
    found = {}
    try:
        r = session.get(urljoin(base_url, "/wp-json/wp/v2/plugins"), timeout=config.timeout)
        if r.status_code == 200:
            for p in r.json():
                slug = p.get("plugin", "").split("/")[0]
                if slug:
                    found[slug] = PluginInfo(slug=slug, version=p.get("version"),
                                             detected_via="rest-api-plugins", confidence=100)
    except Exception as _e:
        log.debug("core: %s", _e)
    return found


def detect_plugins_from_wpo_json(session, base_url: str, config: ScannerConfig) -> dict[str, PluginInfo]:
    found = {}
    try:
        url = urljoin(base_url, "/wp-content/uploads/wpo-plugins-tables-list.json")
        r = session.get(url, timeout=config.timeout, allow_redirects=False)
        if r.status_code == 200 and "slug" in r.text:
            for slug in WPO_SLUG_RE.findall(r.text):
                if slug not in found:
                    found[slug] = PluginInfo(slug=slug, version=None,
                                             detected_via="wpo-json-expuesto", confidence=95)
    except Exception as _e:
        log.debug("core: %s", _e)
    return found


def probe_plugin_readme(session, base_url: str, slug: str, config: ScannerConfig) -> Optional[str]:
    """Probe readme.txt for version. Uses module-level session cache to avoid duplicate HTTP requests."""
    _cache_key = f"{base_url}::{slug}"
    if _cache_key in _PROBE_CACHE:
        return _PROBE_CACHE[_cache_key]
    try:
        url = urljoin(base_url, f"/wp-content/plugins/{slug}/readme.txt")
        r = session.get(url, timeout=min(config.timeout, 6), allow_redirects=False)
        if r.status_code == 200 and len(r.text) > 10:
            m = re.search(r'Stable tag:\s*([0-9][0-9a-zA-Z._-]*)', r.text, re.I)
            if m:
                _PROBE_CACHE[_cache_key] = m.group(1)
                return m.group(1)
    except Exception as _e:
        log.debug("core: %s", _e)
    _PROBE_CACHE[_cache_key] = None
    return None

                                                                                       
_PROBE_CACHE: dict[str, Optional[str]] = {}


def get_plugin_latest_wporg(session, slug: str, config: ScannerConfig) -> Optional[str]:
    try:
        r = session.get(
            f"https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&slug={slug}&fields=version",
            timeout=config.timeout)
        if r.status_code == 200:
            return r.json().get("version")
    except Exception as _e:
        log.debug("core: %s", _e)
    return None


                                                                               
          
                                                                               

THEME_ASSET_RE = re.compile(r'/wp-content/themes/([a-z0-9_-]+)/[^"\'<>\s]*\?ver=([0-9][0-9a-zA-Z._-]*)', re.I)
THEME_SLUG_RE  = re.compile(r'/wp-content/themes/([a-z0-9_-]+)/', re.I)


def detect_themes_from_html(html: str) -> dict[str, PluginInfo]:
    found: dict[str, PluginInfo] = {}
    for m in THEME_ASSET_RE.finditer(html):
        slug, ver = m.group(1), m.group(2)
        if slug not in found:
            found[slug] = PluginInfo(slug=slug, version=ver,
                                     detected_via="html-asset", confidence=93, type="theme")
    for m in THEME_SLUG_RE.finditer(html):
        slug = m.group(1)
        if slug not in found:
            found[slug] = PluginInfo(slug=slug, version=None,
                                     detected_via="html-path", confidence=76, type="theme")
    return found


def probe_theme_style(session, base_url: str, slug: str, config: ScannerConfig) -> Optional[str]:
    try:
        url = urljoin(base_url, f"/wp-content/themes/{slug}/style.css")
        r = session.get(url, timeout=config.timeout, allow_redirects=False)
        if r.status_code == 200:
            m = re.search(r'^Version:\s*([0-9][0-9a-zA-Z._-]*)', r.text, re.I | re.M)
            if m:
                return m.group(1)
    except Exception as _e:
        log.debug("core: %s", _e)
    return None


def probe_theme_parent(session, base_url: str, slug: str, config: ScannerConfig) -> Optional[str]:
    """
    MEJORA #5: Lee style.css del tema buscando 'Template:' que indica child theme.
    Devuelve el slug del tema padre o None si es tema raíz.
    """
    try:
        url = urljoin(base_url, f"/wp-content/themes/{slug}/style.css")
        r = session.get(url, timeout=config.timeout, allow_redirects=False)
        if r.status_code == 200:
            m = re.search(r'^Template:\s*([a-z0-9_-]+)', r.text, re.I | re.M)
            if m:
                parent = m.group(1).strip().lower()
                if parent and parent != slug:
                    return parent
    except Exception as _e:
        log.debug("core probe_theme_parent: %s", _e)
    return None


def get_theme_latest_wporg(session, slug: str, config: ScannerConfig) -> Optional[str]:
    try:
        r = session.get(
            f"https://api.wordpress.org/themes/info/1.1/?action=theme_information&slug={slug}&fields=version",
            timeout=config.timeout)
        if r.status_code == 200:
            return r.json().get("version")
    except Exception as _e:
        log.debug("core: %s", _e)
    return None


                                                                               
                                       
                                                                               

def enumerate_users(session, base_url: str, config: ScannerConfig) -> list[UserInfo]:
    users = []
    found_ids: set[int] = set()

                                                                       
    for endpoint in [
        "/wp-json/wp/v2/users?per_page=10&context=view",
        "/wp-json/wp/v2/users?per_page=10",
    ]:
        try:
            r = session.get(urljoin(base_url, endpoint), timeout=config.timeout)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    for u in data:
                        uid = u.get("id", 0)
                        if uid not in found_ids:
                            found_ids.add(uid)
                            users.append(UserInfo(
                                id=uid,
                                login=u.get("slug") or u.get("username"),
                                display_name=u.get("name"),
                                source="rest-api"
                            ))
                    if users:
                        break
        except Exception as _e:
            log.debug("core: %s", _e)

                                                         
    if not users:
        import random as _random
        for uid in range(1, 6):
            try:
                r = session.get(
                    urljoin(base_url, f"/?author={uid}"),
                    timeout=config.timeout, allow_redirects=True
                )
                                             
                m = re.search(r'/author/([^/?\"\'<>\s]+)', r.url)
                if m and r.status_code == 200 and uid not in found_ids:
                    found_ids.add(uid)
                    users.append(UserInfo(
                        id=uid,
                        login=m.group(1),
                        display_name=None,
                        source="author-redirect"
                    ))
                                                                         
                                                                        
                                                         
                time.sleep(max(_random.uniform(0.4, 1.2), getattr(config, 'request_delay', 0.5)))
            except Exception as _e:
                log.debug("core: %s", _e)

                                          
    if not users:
        try:
            r = session.get(urljoin(base_url, "/?feed=rss2"), timeout=config.timeout)
            if r.status_code == 200:
                for m in re.finditer(r'<dc:creator><!\[CDATA\[([^\]]+)\]\]>', r.text):
                    login = m.group(1).strip()
                    if login and login not in [u.login for u in users]:
                        users.append(UserInfo(
                                                                                     
                                                                                              
                            id=0,
                            login=login,
                            display_name=login,
                            source="rss-feed"
                        ))
        except Exception as _e:
            log.debug("core: %s", _e)

    return users[:15]             


                                                                               
                                           
                                                                               

SENSITIVE_PATHS: list[tuple[str, str, str]] = [
                                                                            
    ("/wp-config.php",               "Credenciales de base de datos expuestas",              "critical"),
    ("/wp-config.php.bak",           "Backup de configuración con credenciales",             "critical"),
    ("/wp-config.php~",              "Backup temporal de configuración",                     "critical"),
    ("/wp-config.php.old",           "Backup antiguo de configuración",                      "critical"),
    ("/wp-config.php.save",          "Copia de seguridad de configuración (vim)",             "critical"),
    ("/wp-config-backup.php",        "Backup de configuración explícito",                    "critical"),
    ("/wp-config.php.orig",          "Copia original de wp-config expuesta",                 "critical"),
    ("/wp-config.php.swp",           "Archivo swap vim de wp-config",                        "critical"),
                                                                            
    ("/.env",                        "Variables de entorno con secretos expuestas",          "critical"),
    ("/.env.production",             "Variables de entorno de producción expuestas",         "critical"),
    ("/.env.local",                  "Variables de entorno local expuestas",                 "critical"),
    ("/wp-content/.env",             ".env en wp-content expuesto",                          "critical"),
                                                                            
    ("/.htpasswd",                   "Archivo de contraseñas HTTP expuesto",                 "critical"),
    ("/.aws/credentials",            "AWS credentials expuestas",                            "critical"),
    ("/.aws/config",                 "Configuración AWS expuesta",                           "critical"),
    ("/wp-content/uploads/aws-credentials", "AWS credentials en uploads",                   "critical"),
                                                                            
    ("/.git/config",                 "Repositorio Git expuesto — posible fuente de código",  "critical"),
    ("/.git/HEAD",                   "Repositorio Git: ref HEAD expuesto",                   "critical"),
    ("/.svn/entries",                "Repositorio SVN expuesto",                             "critical"),
    ("/.gitignore",                  ".gitignore expuesto (rutas internas reveladas)",        "medium"),
                                                                           
    ("/dump.sql",                    "Volcado de base de datos expuesto",                    "critical"),
    ("/backup.sql",                  "Volcado SQL de backup accesible",                      "critical"),
    ("/database.sql",                "Volcado SQL de base de datos accesible",               "critical"),
    ("/wp-content/database.sql",     "Volcado SQL expuesto en wp-content",                   "critical"),
    ("/backup/database.sql.gz",      "Backup comprimido de BD en /backup/",                  "critical"),
                                                                            
    ("/wp-content/backup.zip",       "ZIP de backup en wp-content",                         "critical"),
    ("/public_html.zip",             "ZIP de public_html en raíz",                           "critical"),
                                                                            
    ("/phpinfo.php",                 "Información PHP completa expuesta",                    "critical"),
    ("/phpmyadmin/",                 "phpMyAdmin expuesto al público",                       "critical"),
    ("/pma/",                        "phpMyAdmin (ruta alternativa /pma) expuesto",          "critical"),
    ("/shell.php",                   "shell.php accesible (webshell)",                       "critical"),
    ("/c99.php",                     "c99 webshell",                                         "critical"),
    ("/wp-content/uploads/shell.php","Shell en uploads",                                     "critical"),
    ("/wp-content/plugins/installer.php","PHP installer de plugin expuesto",                "critical"),
    ("/wp-admin/install.php",        "Script de instalación de WordPress accesible",         "high"),
    ("/wp-admin/upgrade.php",        "Script de actualización de WP accesible",              "high"),
                                                                           
    ("/wp-content/debug.log",        "Log de debug con trazas internas y rutas",             "high"),
    ("/debug.log",                   "Log de errores accesible desde la raíz",               "high"),
    ("/error_log",                   "Log de errores PHP expuesto",                          "high"),
                                                                            
    ("/wp-content/uploads/",         "Directory listing activo en directorio de uploads",    "high"),
    ("/wp-content/backup/",          "Directorio de backups accesible",                      "critical"),
    ("/backup/",                     "Directorio de backups en raíz accesible",              "critical"),
                                                                            
    ("/wp-json/wp/v2/users",         "Enumeración de usuarios sin autenticación (REST API)", "high"),
    ("/xmlrpc.php",                  "XML-RPC activo — vector de fuerza bruta y DDoS",       "high"),
    ("/wp-login.php?action=register","Registro de usuarios público activo",                  "high"),
                                                                            
    ("/composer.json",               "Dependencias del proyecto expuestas",                  "high"),
    ("/composer.lock",               "Versiones exactas de dependencias expuestas",          "high"),
                                                                            
    ("/readme.html",                 "Versión de WordPress revelada en readme.html",         "medium"),
    ("/.htaccess",                   "Reglas de configuración Apache expuestas",             "medium"),
    ("/wp-admin/",                   "Panel de administración accesible sin redirección",    "medium"),
    ("/server-status",               "Estado del servidor Apache expuesto",                  "high"),
    ("/robots.txt",                  "Robots.txt puede revelar rutas privadas del sitio",    "info"),
    ("/sitemap.xml",                 "Sitemap expone estructura interna de URLs",             "info"),
]

                                                                       
                                                                       
                                                                        
NORMAL_WP_PATHS = {
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml",
    "/wlwmanifest.xml", "/wp-links-opml.php", "/wp-trackback.php",
    "/wp-admin/admin-ajax.php", "/wp-cron.php", "/wp-activate.php",
    "/wp-signup.php", "/wp-register.php", "/wp-mail.php",
    "/wp-content/plugins/akismet/",
    "/wp-content/themes/",
    "/wp-content/",
    "/wp-admin/",
}

DIR_LISTING_SIGNALS = ["Index of /", "Parent Directory", "<title>Index of", "Directory listing for"]
CONFIG_SIGNALS = ["DB_PASSWORD", "DB_HOST", "define(", "APP_KEY", "DB_CONNECTION",
                  "MAIL_PASSWORD", "PHP Fatal", "PHP Warning", "Stack trace",
                  "<?php", "[client]", "[error]", "base64_decode("]


def _is_real_content(resp: requests.Response, path: str) -> tuple[bool, str]:
    """
    FIX #2: Determina si el contenido de una respuesta 200 representa
    un hallazgo de seguridad real.

    FIX-3: Las señales de contenido sensible (CONFIG_SIGNALS, DIR_LISTING_SIGNALS,
    phpinfo) se evalúan ANTES de comprobar NORMAL_WP_PATHS. Antes, rutas como
    /robots.txt con un 'define(' en su contenido pasaban directo al return False,
    silenciando un hallazgo real.
    """
    text = resp.text.strip()
    if not text or len(text) < 15:
        return False, ""

                                                                                           

                                                  
    for sig in DIR_LISTING_SIGNALS:
        if sig in resp.text:
            return True, "DIRECTORY LISTING ACTIVO"

                                                             
    for sig in CONFIG_SIGNALS:
        if sig in resp.text:
            return True, f"Contiene: {sig}"

             
    if "phpinfo()" in resp.text or ("PHP Version" in resp.text and "PHP License" in resp.text):
        return True, "phpinfo() expuesto"

                                        
    if path.endswith(".json") and (resp.text.lstrip().startswith("{") or resp.text.lstrip().startswith("[")):
        return True, "JSON expuesto"

                                                                                   
                                                                      
                                                                                               
    if path in NORMAL_WP_PATHS or any(path.startswith(p) for p in NORMAL_WP_PATHS if p.endswith("/")):
        return False, ""

                                                                      
                                                                                     
    if len(text) > 150:
        low = resp.text[:300].lower()
        if "404" not in low and "not found" not in low and "access denied" not in low:
            return True, ""

    return False, ""


def check_xmlrpc(session, base_url: str, config: ScannerConfig) -> bool:
    try:
        payload = "<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>"
        r = session.post(urljoin(base_url, "/xmlrpc.php"), data=payload,
                         headers={"Content-Type": "text/xml"}, timeout=config.timeout)
        return r.status_code == 200 and "methodResponse" in r.text
    except Exception:
        return False


def check_exposed_files(session, base_url: str, config: ScannerConfig,
                        timeout_total: int = 45) -> list[ExposedFile]:
    """Verifica archivos sensibles con timeout global y circuit breaker."""
    from urllib.parse import urlparse as _up
    _host = _up(base_url).hostname or base_url

                                                                       
                                                                                 
    _circuit_breaker.record_success(_host)

    def probe(path: str, description: str, severity: str) -> Optional[ExposedFile]:
                                                             
        if _circuit_breaker.is_open(_host):
            return None
        try:
            if config.request_delay > 0:
                import time as _t; _t.sleep(config.request_delay)
            url = urljoin(base_url, path)
            r = session.get(url, timeout=min(config.timeout, 6), allow_redirects=True)
            _circuit_breaker.record_success(_host)
            if r.status_code != 200:
                return None
            is_real, extra = _is_real_content(r, path)
            if is_real:
                return ExposedFile(path=path, url=url,
                                   description=description, severity=severity, extra=extra)
        except (requests.exceptions.ConnectionError,
                requests.exceptions.ConnectTimeout) as _e:
            _circuit_breaker.record_failure(_host)
            log.debug("core cb: %s", _e)
        except Exception as _e:
            log.debug("core: %s", _e)
        return None

    found = []
    with ThreadPoolExecutor(max_workers=config.max_workers) as ex:
        futures = {ex.submit(probe, p, d, s): p for p, d, s in SENSITIVE_PATHS}
        try:
            for future in as_completed(futures, timeout=timeout_total):
                try:
                    res = future.result()
                    if res:
                        found.append(res)
                except Exception as _e:
                    log.debug("core: %s", _e)
        except FuturesTimeout:
            log.warning("Timeout global en check_exposed_files (%ds)", timeout_total)

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    found.sort(key=lambda f: sev_order.get(f.severity, 99))
    return found


                                                                               
                           
                                                                               

SECURITY_HEADERS = {
    "Strict-Transport-Security":    "HSTS ausente — HTTPS no se fuerza",
    "Content-Security-Policy":      "CSP ausente — XSS sin mitigar",
    "X-Frame-Options":              "Clickjacking posible",
    "X-Content-Type-Options":       "MIME sniffing no bloqueado",
    "Referrer-Policy":              "Política de referrer no definida",
    "Permissions-Policy":           "Permisos API del navegador sin restringir",
    "X-XSS-Protection":             "Filtro XSS del navegador no activado",
    "Cross-Origin-Opener-Policy":   "Aislamiento de origen no configurado",
    "Cross-Origin-Resource-Policy": "Política CORS sin definir",
    "Cache-Control":                "Control de caché no configurado",
}
DANGEROUS_HEADERS = {
    "X-Powered-By":  "Versión de tecnología revelada",
    "Server":        "Software de servidor revelado",
    "X-Generator":   "Generador CMS revelado en cabecera",
}


def check_security_headers(headers: dict) -> tuple[list[str], list[str], list[str]]:
    """
    Mejora #7: Análisis profundo de cabeceras de seguridad.
    Verifica no solo presencia sino también calidad del valor.
    """
    hl = {k.lower(): v for k, v in headers.items()}
    issues, ok, leaks = [], [], []

    for header, problem in SECURITY_HEADERS.items():
        header_lower = header.lower()
        if header_lower in hl:
            val = hl[header_lower]

                                                               
            quality_issue = None

            if header == "Strict-Transport-Security":
                m = re.search(r'max-age\s*=\s*(\d+)', val, re.I)
                if m and int(m.group(1)) < 15768000:             
                    quality_issue = f"HSTS max-age insuficiente ({m.group(1)}s) — mínimo 15768000"
                elif "includesubdomains" not in val.lower():
                    quality_issue = "HSTS sin includeSubDomains"

            elif header == "Content-Security-Policy":
                if "'unsafe-inline'" in val:
                    quality_issue = "CSP contiene 'unsafe-inline' — XSS sin mitigar"
                elif "'unsafe-eval'" in val:
                    quality_issue = "CSP contiene 'unsafe-eval' — eval() permitido"
                elif re.search(r"(?:script-src|default-src)[^;]*\*", val):
                    quality_issue = "CSP con wildcard (*) en script-src — protección nula"

            elif header == "X-Frame-Options":
                if val.upper() not in ("DENY", "SAMEORIGIN"):
                    quality_issue = f"X-Frame-Options valor no seguro: {val}"

            elif header == "Cache-Control":
                if "no-store" not in val.lower() and "private" not in val.lower():
                    quality_issue = "Cache-Control sin no-store/private — posible caché de datos sensibles"

            elif header == "Referrer-Policy":
                unsafe_policies = ("unsafe-url", "no-referrer-when-downgrade")
                if any(p in val.lower() for p in unsafe_policies):
                    quality_issue = f"Referrer-Policy '{val}' expone URLs completas"

            if quality_issue:
                issues.append(f"{header} — {quality_issue}")
            else:
                ok.append(f"{header}: {val[:80]}")
        else:
            issues.append(f"{header} — {problem}")

    for header, problem in DANGEROUS_HEADERS.items():
        if header.lower() in hl:
            leaks.append(f"{header}: {hl[header.lower()]} — {problem}")

    return issues, ok, leaks


                                                                               
                       
                                                                               

MALWARE_PATTERNS = [
    (re.compile(r'eval\s*\(\s*base64_decode\s*\(', re.I),
     "eval(base64_decode()) — código PHP ofuscado"),
    (re.compile(r'document\.write\s*\(\s*unescape\s*\(', re.I),
     "document.write(unescape()) — JS ofuscado"),
    (re.compile(r'<iframe[^>]+style=["\'][^"\']*(?:display:\s*none|visibility:\s*hidden|width:\s*0)', re.I),
     "iFrame oculto — posible malware"),
    (re.compile(r'<a[^>]+style=["\'][^"\']*(?:display:\s*none|visibility:\s*hidden|opacity:\s*0)', re.I),
     "Enlace oculto — posible SEO spam"),
    (re.compile(r'(?:cialis|viagra|casino|poker|porn|xxx|payday\s*loan)\s+(?:online|cheap|buy|free)', re.I),
     "SEO spam — keywords farmacéuticas/juego"),
    (re.compile(r'window\.location\s*=\s*["\']https?://(?!(?:www\.)?(?:google|youtube|facebook|twitter))', re.I),
     "Redirección JS sospechosa"),
    (re.compile(r'@import\s+url\s*\(\s*["\']https?://[^"\']+["\']', re.I),
     "Importación CSS externa sospechosa"),
    (re.compile(r'<script[^>]*>(?:[^<]{0,50})?(?:atob|fromCharCode|String\.fromCharCode)', re.I),
     "Ofuscación JS con atob/fromCharCode"),
]


def detect_malware(html: str, base_url: str) -> list[str]:
    return [desc for pattern, desc in MALWARE_PATTERNS if pattern.search(html)]


                                                                               
        
                                                                               

                                                                               
                                                                  
                                                                               

                                                           
                                                             
                                                         
WP_ASSET_HASH_DB: dict[str, dict] = {
                                                                 
                                                          
    "wp-login.php": {
                                                                           
    },
}

WP_ORG_CHECKSUMS_API = "https://api.wordpress.org/core/checksums/1.0/?version={version}&locale=en_US"

                                                               
WP_PROBE_ASSETS = [
    ("/license.txt",         re.compile(r'GNU General Public License v(\d+)',  re.I), "license"),
    ("/readme.html",         re.compile(r'Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.I), "readme"),
    ("/wp-includes/version.php", re.compile(r"\s*=\s*'([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I), "version.php"),
    ("/wp-links-opml.php",  re.compile(r'generator="WordPress/([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.I), "opml"),
]


def detect_version_by_assets(session, base_url: str,
                              config: "ScannerConfig") -> Optional[tuple[str, str]]:
    """
    Mejora #2: Detecta la versión de WP descargando assets públicos y
    comparando su contenido contra patrones conocidos.
    Devuelve (version, source) o None si no detecta.
    """
    for path, pattern, source_name in WP_PROBE_ASSETS:
        try:
            url = urljoin(base_url, path)
            r = session.get(url, timeout=min(config.timeout, 8), allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 50:
                m = pattern.search(r.text)
                if m:
                    version = m.group(1)
                                                         
                    if re.match(r'^[0-9]+\.[0-9]+(\.[0-9]+)?$', version):
                        log.debug("Versión detectada por asset %s: %s", source_name, version)
                        return version, f"asset-{source_name}"
        except Exception as _e:
            log.debug("core: %s", _e)
    return None


def detect_version_by_hash(session, base_url: str,
                            config: "ScannerConfig",
                            candidate_version: Optional[str] = None) -> Optional[str]:
    """
    Mejora #2: Confirma/precisa la versión descargando wp-includes/version.php
    y comparando su hash SHA256 contra la API de checksums de wordpress.org.
    Solo se activa si ya tenemos una versión candidata (para no hacer peticiones innecesarias).
    """
    if not candidate_version:
        return None

                                                       
    ver_parts = candidate_version.split(".")
    if len(ver_parts) < 2:
        return None

    try:
                                                        
        url = urljoin(base_url, "/wp-includes/version.php")
        r = session.get(url, timeout=min(config.timeout, 6), allow_redirects=False)
        if r.status_code != 200 or not r.text:
            return None

                                              
        target_hash = hashlib.md5(r.content).hexdigest()

                                                              
        checksums_url = WP_ORG_CHECKSUMS_API.format(version=candidate_version)
        rc = session.get(checksums_url, timeout=min(config.timeout, 8))
        if rc.status_code == 200:
            data = rc.json()
            checksums = data.get("checksums", {})
            expected_hash = checksums.get("wp-includes/version.php")
            if expected_hash and expected_hash.lower() == target_hash.lower():
                log.info("Versión confirmada por hash MD5: %s", candidate_version)
                return candidate_version
    except Exception as e:
        log.debug("Hash check error: %s", e)

    return None


                                                                               
                                                        
                                                                               

                                                     
LEGIT_JS_DOMAINS = {
    "jquery.com", "cdnjs.cloudflare.com", "ajax.googleapis.com",
    "code.jquery.com", "unpkg.com", "cdn.jsdelivr.net", "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com", "use.fontawesome.com", "kit.fontawesome.com",
    "assets.squarespace.com", "connect.facebook.net", "platform.twitter.com",
    "ssl.google-analytics.com", "www.googletagmanager.com", "www.google-analytics.com",
    "analytics.google.com", "googleads.g.doubleclick.net", "pagead2.googlesyndication.com",
    "www.googleadservices.com", "static.hotjar.com", "script.hotjar.com",
    "cdn.segment.com", "js.stripe.com", "js.paypal.com",
    "fast.wistia.com", "player.vimeo.com", "www.youtube.com",
    "embed.typeform.com", "js.hsforms.net", "js.hubspot.com",
    "cdn.cookielaw.org", "cdn.onetrust.com", "consent.cookiebot.com",
    "static.cloudflareinsights.com", "challenges.cloudflare.com",
    "wp.com", "s0.wp.com", "s1.wp.com", "s2.wp.com",
}

                                                         
MALICIOUS_JS_PATTERNS = [
    (re.compile(r'eval\s*\(\s*(?:atob|unescape|String\.fromCharCode)\s*\(', re.I),
     "Ejecución de código ofuscado (eval+decode)"),
    (re.compile(r'document\.write\s*\(\s*(?:unescape|atob|String\.fromCharCode)', re.I),
     "document.write con datos ofuscados"),
    (re.compile(r'fromCharCode\s*\(\s*(?:\d+\s*,\s*){10,}', re.I),
     "Cadena larga de charCodes (shellcode)"),
    (re.compile(r'(?:new|)Function\s*\([^)]*\$\s*\(', re.I),
     "new Function() con código dinámico"),
    (re.compile(r'window\.(?:location|top\.location)\s*(?:=|href)\s*["\'][^"\']{3,}["\']', re.I),
     "Redirección forzada en script externo"),
    (re.compile(r'crypto(?:currency|jacking|miner|\.mine)', re.I),
     "Cryptominer detectado en script externo"),
    (re.compile(r'coinhive|coinimp|cryptoloot|webminerpool', re.I),
     "Librería de criptominería conocida"),
    (re.compile(r'(?:keylog|password\s*steal|credential\s*harvest)', re.I),
     "Patrón de keylogger/credential harvesting"),
]

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\'>]+)["\']', re.I)


def detect_external_js_threats(session, html: str, base_url: str,
                                 config: "ScannerConfig") -> list[str]:
    """
    Mejora #4: Analiza scripts JS externos cargados por la página.
    - Detecta scripts desde dominios no reconocidos (sospechosos)
    - Descarga hasta MAX_JS scripts para analizar su contenido
    - Busca patrones maliciosos conocidos
    """
    from urllib.parse import urlparse

    MAX_JS = 5                                              
    threats: list[str] = []
    scripts_checked = 0

    external_scripts: list[str] = []
    for m in SCRIPT_SRC_RE.finditer(html):
        src = m.group(1).strip()
        if src.startswith(("http://", "https://", "//")):
            if src.startswith("//"):
                src = "https:" + src
            parsed = urlparse(src)
            domain = parsed.hostname or ""
                                                                  
            base_parsed = urlparse(base_url)
            base_domain = base_parsed.hostname or ""
            if domain and domain != base_domain and domain not in base_domain:
                                            
                is_legit = any(
                    domain == ld or domain.endswith("." + ld)
                    for ld in LEGIT_JS_DOMAINS
                )
                if not is_legit:
                    external_scripts.append((src, domain))

    for src, domain in external_scripts[:MAX_JS]:
        try:
            r = session.get(src, timeout=min(config.timeout, 6), allow_redirects=True)
            if r.status_code == 200:
                scripts_checked += 1
                content = r.text[:50000]                 
                for pattern, desc in MALICIOUS_JS_PATTERNS:
                    if pattern.search(content):
                        threats.append(f"{desc} — en {domain}")
                        break                                        
        except Exception as _e:
            log.debug("core: %s", _e)

                                                                                   
    for src, domain in external_scripts:
        if re.search(r':\d{4,5}', domain) or domain.endswith(".xyz") or domain.endswith(".top"):
            threat = f"Script externo desde dominio sospechoso: {domain}"
            if threat not in threats:
                threats.append(threat)

    return threats


                                                                               
                                                      
                                                                               

SERVER_SIGNATURES = {
                                                   
    "Apache":   ("apache",    "Apache",          "web_server"),
    "Nginx":    ("nginx",     "Nginx",           "web_server"),
    "LiteSpeed":("litespeed", "LiteSpeed",       "web_server"),
    "IIS":      ("microsoft-iis", "Microsoft IIS", "web_server"),
    "Caddy":    ("caddy",     "Caddy",           "web_server"),
    "OpenResty":("openresty", "OpenResty",       "web_server"),
}

PHP_PATTERNS = [
    re.compile(r'PHP/([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.I),                            
    re.compile(r'X-Powered-By:.*PHP/([0-9]+\.[0-9]+)', re.I),
    re.compile(r'PHPSESSID', re.I),                                  
]

PHP_EOL_VERSIONS = {
    "5": "EOL (2018)", "7.0": "EOL (2019)", "7.1": "EOL (2019)",
    "7.2": "EOL (2020)", "7.3": "EOL (2021)", "7.4": "EOL (2022)",
    "8.0": "EOL (2023)",
}


def fingerprint_server_stack(headers: dict, html: str,
                              cookies: list = None) -> dict:
    """
    Mejora #9: Análisis completo del stack tecnológico del servidor.
    Devuelve dict con web_server, php_version, php_eol, cdn, framework, etc.
    
    FIX #10: El parámetro 'cookies' ahora se usa para detectar tecnologías
    por nombre de cookie (antes estaba definido pero nunca se leía).
    """
    stack: dict = {
        "web_server":      None,
        "web_server_version": None,
        "php_version":     None,
        "php_eol":         None,
        "php_vulnerable":  False,
        "cdn":             None,
        "framework":       None,
        "os_hint":         None,
        "info_leaks":      [],
    }

    hl = {k.lower(): v for k, v in headers.items()}
    server_header = hl.get("server", "")
    powered_by    = hl.get("x-powered-by", "")

                
    server_lower = server_header.lower()
    for key, (pattern, name, cat) in SERVER_SIGNATURES.items():
        if pattern in server_lower:
            stack["web_server"] = name
                             
            ver_m = re.search(r'(?:Apache|nginx|LiteSpeed|IIS)[/\s]+([0-9]+\.[0-9.]+)',
                              server_header, re.I)
            if ver_m:
                stack["web_server_version"] = ver_m.group(1)
            break

                                 
    if "ubuntu" in server_lower:   stack["os_hint"] = "Ubuntu"
    elif "debian" in server_lower: stack["os_hint"] = "Debian"
    elif "centos" in server_lower: stack["os_hint"] = "CentOS"
    elif "win" in server_lower:    stack["os_hint"] = "Windows"
    elif "freebsd" in server_lower: stack["os_hint"] = "FreeBSD"

         
    for header_val in [powered_by, server_header]:
        m = re.search(r'PHP/([0-9]+\.[0-9]+(?:\.[0-9]+)?)', header_val, re.I)
        if m:
            stack["php_version"] = m.group(1)
            break

    if stack["php_version"]:
        ver = stack["php_version"]
        major = ver.split(".")[0]
        major_minor = ".".join(ver.split(".")[:2])
        eol = PHP_EOL_VERSIONS.get(major_minor) or PHP_EOL_VERSIONS.get(major)
        if eol:
            stack["php_eol"] = eol
            stack["php_vulnerable"] = True

         
    if "cf-ray" in hl:          stack["cdn"] = "Cloudflare"
    elif "x-fastly" in hl or "x-fastly-request-id" in hl: stack["cdn"] = "Fastly"
    elif "x-akamai-transformed" in hl: stack["cdn"] = "Akamai"
    elif "x-amz-cf-id" in hl:   stack["cdn"] = "AWS CloudFront"
    elif "x-bunny-ip" in hl or "bunny" in server_lower: stack["cdn"] = "BunnyCDN"
    elif "x-cdn" in hl:         stack["cdn"] = hl.get("x-cdn", "CDN")

                                
    if "wp-content" in html:           stack["framework"] = "WordPress"
    elif "Joomla" in html:             stack["framework"] = "Joomla"
    elif "Drupal" in html:             stack["framework"] = "Drupal"
    elif "laravel" in html.lower():    stack["framework"] = "Laravel"

                                                                   
                                                              
    if cookies:
        cookies_str = " ".join(cookies).lower()
        if "phpsessid" in cookies_str and not stack["php_version"]:
            stack["php_version"] = "detectado-por-cookie"
        if "jsessionid" in cookies_str:
            stack["framework"] = stack.get("framework") or "Java/JSP"
        if "asp.net_sessionid" in cookies_str or "aspxauth" in cookies_str:
            stack["framework"] = stack.get("framework") or "ASP.NET"
        if "laravel_session" in cookies_str:
            stack["framework"] = "Laravel"
        if "ci_session" in cookies_str:
            stack["framework"] = stack.get("framework") or "CodeIgniter"
        if "django_" in cookies_str or "csrftoken" in cookies_str:
            stack["framework"] = stack.get("framework") or "Django"
        if "rack.session" in cookies_str:
            stack["framework"] = stack.get("framework") or "Ruby/Rack"

                
    if server_header and server_header not in ("-", ""):
        stack["info_leaks"].append(f"Server: {server_header}")
    if powered_by and powered_by not in ("-", ""):
        stack["info_leaks"].append(f"X-Powered-By: {powered_by}")
    x_gen = hl.get("x-generator", "")
    if x_gen:
        stack["info_leaks"].append(f"X-Generator: {x_gen}")

    return stack


                                                                               
                                                        
                                                                               

HSTS_MIN_MAX_AGE = 15768000                       


def analyze_csp(csp_value: str) -> dict:
    """Analiza el valor de Content-Security-Policy en detalle."""
    analysis = {
        "present":      True,
        "unsafe_inline": False,
        "unsafe_eval":   False,
        "wildcard_src":  False,
        "missing_default_src": False,
        "issues":        [],
        "score":         100,                               
    }

    csp_lower = csp_value.lower()

    if "'unsafe-inline'" in csp_lower:
        analysis["unsafe_inline"] = True
        analysis["issues"].append("'unsafe-inline' permite XSS inline")
        analysis["score"] -= 30

    if "'unsafe-eval'" in csp_lower:
        analysis["unsafe_eval"] = True
        analysis["issues"].append("'unsafe-eval' permite eval() — XSS vector")
        analysis["score"] -= 25

    if re.search(r"(?:script-src|default-src)[^;]*\*", csp_lower):
        analysis["wildcard_src"] = True
        analysis["issues"].append("Wildcard (*) en script-src/default-src")
        analysis["score"] -= 20

    if "default-src" not in csp_lower and "script-src" not in csp_lower:
        analysis["missing_default_src"] = True
        analysis["issues"].append("Falta default-src o script-src")
        analysis["score"] -= 20

    if "http:" in csp_lower and "upgrade-insecure-requests" not in csp_lower:
        analysis["issues"].append("Permite recursos HTTP sin upgrade-insecure-requests")
        analysis["score"] -= 10

    analysis["score"] = max(0, analysis["score"])
    return analysis


def analyze_hsts(hsts_value: str) -> dict:
    """Analiza el valor de Strict-Transport-Security en detalle."""
    analysis = {
        "present":       True,
        "max_age":       0,
        "max_age_ok":    False,
        "include_subdomains": False,
        "preload":       False,
        "issues":        [],
    }

    m = re.search(r'max-age\s*=\s*(\d+)', hsts_value, re.I)
    if m:
        analysis["max_age"] = int(m.group(1))
        analysis["max_age_ok"] = analysis["max_age"] >= HSTS_MIN_MAX_AGE
        if not analysis["max_age_ok"]:
            months = analysis["max_age"] // 2592000
            analysis["issues"].append(
                f"max-age insuficiente ({months}m) — se recomienda >= 6 meses"
            )
    else:
        analysis["issues"].append("max-age no especificado")

    if "includesubdomains" in hsts_value.lower():
        analysis["include_subdomains"] = True
    else:
        analysis["issues"].append("includeSubDomains no configurado")

    if "preload" in hsts_value.lower():
        analysis["preload"] = True

    return analysis


def analyze_cookies(set_cookie_headers: list[str]) -> list[str]:
    """Analiza las cabeceras Set-Cookie buscando flags de seguridad faltantes."""
    issues = []
    for cookie in set_cookie_headers:
        cookie_lower = cookie.lower()
        name = cookie.split("=")[0].strip()
        if "secure" not in cookie_lower:
            issues.append(f"Cookie '{name}' sin flag Secure (transmisible por HTTP)")
        if "httponly" not in cookie_lower:
            issues.append(f"Cookie '{name}' sin flag HttpOnly (accesible vía JS)")
        if "samesite" not in cookie_lower:
            issues.append(f"Cookie '{name}' sin SameSite (vulnerable a CSRF)")
    return issues


def check_ssl(hostname: str) -> SSLInfo:
    info = SSLInfo()
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=8),
            server_hostname=hostname,
        ) as ssock:
            cert = ssock.getpeercert()
            info.valid = True
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                                                                                           
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                not_after = not_after.replace(tzinfo=timezone.utc)
                info.days_left = (not_after - datetime.now(timezone.utc)).days
                info.expired   = info.days_left < 0
            issuer  = dict(x[0] for x in cert.get("issuer", []))
            subject = dict(x[0] for x in cert.get("subject", []))
            info.issuer  = issuer.get("organizationName", issuer.get("commonName", ""))
            info.subject = subject.get("commonName", "")
    except Exception as e:
        info.valid = False
        info.error = str(e)[:120]
    return info


                                                                               
                        
                                                                               

WAF_SIGNATURES: dict[str, list] = {
    "Cloudflare": [
        ("header", "cf-ray"),
        ("header", "cf-cache-status"),
        ("header", "server", "cloudflare"),
        ("body",   "__cf_bm"),
        ("body",   "cdn-cgi/"),
        ("header", "cf-request-id"),
    ],
    "Sucuri WAF": [
        ("header", "x-sucuri-id"),
        ("header", "x-sucuri-cache"),
        ("body",   "sucuri.net"),
        ("body",   "Access Denied - Sucuri Website Firewall"),
    ],
    "Wordfence": [
        ("body",   "Wordfence Security"),
        ("body",   "wordfence"),
        ("body",   "Generated by Wordfence"),
        ("body",   "Your access to this site has been limited"),
    ],
    "ModSecurity": [
        ("body",   "ModSecurity"),
        ("body",   "mod_security"),
        ("header", "server", "mod_security"),
    ],
    "Imunify360": [
        ("body",   "Imunify360"),
        ("header", "x-imunify360-blocked"),
    ],
    "Barracuda WAF": [
        ("header", "x-b-waf"),
        ("body",   "Barracuda Networks"),
    ],
    "F5 BIG-IP": [
        ("header", "x-cnection"),
        ("header", "x-wa-info"),
        ("body",   "BIG-IP"),
    ],
    "AWS WAF": [
        ("header", "x-amzn-requestid"),
        ("header", "x-amz-cf-id"),
        ("body",   "AWS WAF"),
    ],
    "Akamai": [
        ("header", "x-akamai-transformed"),
        ("header", "akamai-origin-hop"),
        ("body",   "Reference #"),
    ],
    "Fastly CDN": [
        ("header", "x-fastly-request-id"),
        ("header", "x-served-by"),
        ("header", "x-cache-hits"),
    ],
    "SiteGround SG Optimizer": [
        ("header", "x-sg-id"),
    ],
    "Varnish Cache": [
        ("header", "x-varnish"),
        ("header", "via", "varnish"),
    ],
    "Nginx + naxsi": [
        ("body",   "NAXSI_FMT"),
    ],
}


                                                                                   
                                                                                               
def detect_waf(headers: dict, body: str) -> list[str]:
    """
    Detecta WAF / CDN activos basándose en cabeceras HTTP y contenido de respuesta.
    Devuelve lista de strings descriptivos.
    """
    return detect_waf_from_response(headers, body)


                                                                               
                                                            
                                                                               

SENSITIVE_ROBOTS_PATTERNS = [
    "wp-admin", "wp-config", "backup", "database", ".env",
    "admin", "login", "phpmyadmin", "private", "secret",
    "install", "setup", "dashboard", "control", "manage",
]

def analyze_robots_txt(session, base_url: str, config: "ScannerConfig") -> dict:
    """
    Descarga y analiza robots.txt para detectar rutas sensibles reveladas.
    Retorna dict con: present, disallowed_sensitive, allowed_sensitive, warnings.
    """
    result = {
        "present": False,
        "disallowed": [],
        "disallowed_sensitive": [],
        "allowed_sensitive": [],
        "warnings": [],
    }
    try:
        resp = session.get(
            urljoin(base_url, "/robots.txt"),                                                             
            timeout=config.timeout,
            allow_redirects=True,
        )
        if resp.status_code != 200 or "text/plain" not in resp.headers.get("Content-Type",""):
            return result
        if len(resp.text) > 50000:
            return result                            

        result["present"] = True
        lines = resp.text.splitlines()

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            lower = line.lower()

            if lower.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    result["disallowed"].append(path)
                    for pattern in SENSITIVE_ROBOTS_PATTERNS:
                        if pattern in path.lower():
                            result["disallowed_sensitive"].append(path)
                            break
            elif lower.startswith("allow:"):
                path = line.split(":", 1)[1].strip()
                for pattern in SENSITIVE_ROBOTS_PATTERNS:
                    if pattern in path.lower():
                        result["allowed_sensitive"].append(path)
                        result["warnings"].append(
                            f"robots.txt expone ruta sensible en Allow: {path}"
                        )
                        break

                                                                                        
        wp_admin_disallowed = any("wp-admin" in p.lower() for p in result["disallowed"])
        if not wp_admin_disallowed and result["present"]:
            result["warnings"].append(
                "wp-admin no está en Disallow — el panel admin podría estar indexado"
            )

    except Exception as e:
        log.debug("analyze_robots_txt error: %s", e)

    return result


def check_wp_admin_protection(session, base_url: str, config: "ScannerConfig") -> dict:
    """
    Verifica si wp-admin está correctamente protegido:
    - Sin redirección directa al login = posible exposición
    - Detecta Basic Auth, 403 Forbidden, o redirección a login custom
    - Detecta si el login form está protegido por limite de intentos (captcha/recaptcha)
    """
    result = {
        "accessible": False,
        "redirects_to_login": False,
        "basic_auth_required": False,
        "forbidden": False,
        "has_captcha": False,
        "login_form_hardened": False,
        "notes": [],
    }
    try:
        resp = session.get(
            urljoin(base_url, "/wp-admin/"),                                                             
            timeout=config.timeout,
            allow_redirects=True,
        )
        code = resp.status_code
        body = resp.text.lower()

        if code == 401:
            result["basic_auth_required"] = True
            result["notes"].append("wp-admin protegido con HTTP Basic Auth ✓")
        elif code == 403:
            result["forbidden"] = True
            result["notes"].append("wp-admin devuelve 403 Forbidden ✓")
        elif code == 200:
            result["accessible"] = True
                                  
            if "wp-login.php" in resp.url or "login" in resp.url:
                result["redirects_to_login"] = True
                result["notes"].append("wp-admin redirige al login (comportamiento normal)")
            else:
                result["notes"].append("⚠ wp-admin accesible directamente sin redirección")

                                                        
            if any(x in body for x in ["recaptcha", "hcaptcha", "g-recaptcha", "cf-turnstile", "captcha"]):
                result["has_captcha"] = True
                result["notes"].append("Login protegido con CAPTCHA ✓")

                                                
            if any(x in body for x in ["limit login", "loginizer", "wordfence", "wp-cerber", "ithemes"]):
                result["login_form_hardened"] = True
                result["notes"].append("Plugin de seguridad detectado en login ✓")

    except Exception as e:
        log.debug("check_wp_admin_protection error: %s", e)

    return result
                                                                               

WPSCAN_API_BASE = "https://wpscan.com/api/v3"

                                              
WPSCAN_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
}


def _wpscan_headers(api_token: str) -> dict:
    """Headers correctos para WPScan API v3."""
    return {
        "Authorization": f"Token token={api_token}",
        "Accept":        "application/json",
        "User-Agent":    "WPVulnScanner/4.0",
    }


def _wpscan_parse_vulns(data: dict, slug: str, version: Optional[str],
                         component_type: str) -> list[Vulnerability]:
    """
    Parsea la respuesta de WPScan API para plugins/temas.
    La API devuelve: { "slug": { "vulnerabilities": [...] } }
    """
    results = []

                                                                  
    vuln_list = []
    if slug in data:
        node = data.get(slug) or {}
        if isinstance(node, dict):
            vuln_list = node.get("vulnerabilities", []) or []
    elif "vulnerabilities" in data:
        vuln_list = data.get("vulnerabilities") or []

    for entry in vuln_list:
        if not isinstance(entry, dict):
            continue
        fixed_in = entry.get("fixed_in")

                                                                                  
        if version and fixed_in:
            try:
                if not _version_lt(version, fixed_in):
                    continue
            except Exception as _e:
                log.debug("core: %s", _e)

              
        refs = entry.get("references") or {}
        if not isinstance(refs, dict):
            refs = {}
        cves = refs.get("cve") or []
        if isinstance(cves, str):
            cves = [cves]

                                                                      
        cvss = entry.get("cvss") or {}
        if not isinstance(cvss, dict):
            cvss = {}
        sev_raw = (
            entry.get("severity") or
            cvss.get("severity", "medium")
        )
        severity = WPSCAN_SEV_MAP.get(str(sev_raw).lower(), Severity.MEDIUM)

                    
        cvss_score = None
        if cvss:
            cvss_score = cvss.get("score")
        elif entry.get("cvss_score"):
            cvss_score = entry["cvss_score"]

                            
        ref_urls = refs.get("url") or []
        if isinstance(ref_urls, str):
            ref_urls = [ref_urls]

        results.append(Vulnerability(
            plugin_slug=slug,
            plugin_version=version,
            cve_id=f"CVE-{cves[0]}" if cves else entry.get("cve_id"),
            title=entry.get("title", "Vulnerabilidad desconocida"),
            severity=severity,
            cvss_score=cvss_score,
            fixed_in=fixed_in,
            references=ref_urls,
            description=(
                f"Versión instalada: {version or 'desconocida'}. "
                f"{'Actualizar a v' + fixed_in + '.' if fixed_in else 'Sin versión de corrección conocida.'}"
            ),
            type=component_type,
            source="wpscan_api",
        ))

    return results


def check_vulns_wpscan(session, plugin: PluginInfo, api_token: str,
                        config: ScannerConfig) -> tuple[list[Vulnerability], str]:
    """
    Consulta WPScan API v3 para plugins y temas.
    Devuelve (vulnerabilidades, mensaje_error).
    Mensaje vacío = éxito.
    """
    if _cb_wpscan.is_open():
        return [], "WPScan API omitida (circuit breaker abierto por fallos previos)"

    endpoint_type = "themes" if plugin.type == "theme" else "plugins"
    url = f"{WPSCAN_API_BASE}/{endpoint_type}/{plugin.slug}"

    try:
        r = session.get(
            url,
            headers=_wpscan_headers(api_token),
            timeout=config.timeout,
            verify=True,                               
        )
    except requests.exceptions.SSLError as e:
        _cb_wpscan.record_failure()
        return [], f"SSL error conectando a WPScan API: {e}"
    except requests.exceptions.ConnectionError as e:
        _cb_wpscan.record_failure()
        return [], f"Sin conexión a WPScan API: {e}"
    except requests.exceptions.Timeout:
        _cb_wpscan.record_failure()
        return [], "Timeout conectando a WPScan API"
    except Exception as e:
        _cb_wpscan.record_failure()
        return [], f"Error inesperado WPScan API: {e}"

                                                                              
    if r.status_code == 200:
        try:
            data = r.json()
        except Exception:
            return [], f"WPScan API devolvió JSON inválido para {plugin.slug}"

        vulns = _wpscan_parse_vulns(data, plugin.slug, plugin.version, plugin.type)
        _cb_wpscan.record_success()
        log.debug("WPScan API [%s] %s → %d vulns", endpoint_type, plugin.slug, len(vulns))
        return vulns, ""

    elif r.status_code == 401:
        msg = "Token WPScan inválido o expirado (401). Verifica tu token en wpscan.com"
        log.warning(msg)
        return [], msg

    elif r.status_code == 403:
        msg = "Acceso denegado a WPScan API (403). Token sin permisos."
        log.warning(msg)
        return [], msg

    elif r.status_code == 404:
                                                                             
        log.debug("WPScan API: %s no encontrado en base de datos (404)", plugin.slug)
        return [], ""                                       

    elif r.status_code == 429:
                                                          
        retry_after = r.headers.get("Retry-After", "?")
        msg = f"Límite de peticiones WPScan API alcanzado (429). Retry-After: {retry_after}s"
        log.warning(msg)
        return [], msg

    elif r.status_code == 422:
        try:
            detail = r.json().get("message", r.text[:100])
        except Exception:
            detail = r.text[:100]
        return [], f"WPScan API error 422: {detail}"

    else:
        try:
            detail = r.json().get("message", r.text[:120])
        except Exception:
            detail = r.text[:120]
        msg = f"WPScan API HTTP {r.status_code} para {plugin.slug}: {detail}"
        log.warning(msg)
        return [], msg


def check_vulns_wpscan_core(session, wp_version: str, api_token: str,
                              config: ScannerConfig) -> tuple[list[Vulnerability], str]:
    """
    Consulta WPScan API para WordPress core.
    Endpoint: /wordpresses/{version_normalizada}
    La versión debe estar normalizada: 6.4.2 → 642, 6.4 → 640, etc.
    """
                                                        
    parts = re.sub(r"[^0-9.]", "", wp_version).split(".")
    while len(parts) < 3:
        parts.append("0")
    version_key = "".join(parts[:3])                      

    url = f"{WPSCAN_API_BASE}/wordpresses/{version_key}"

    try:
        r = session.get(
            url,
            headers=_wpscan_headers(api_token),
            timeout=config.timeout,
            verify=True,
        )
    except requests.exceptions.ConnectionError:
        return [], "Sin conexión a WPScan API (core)"
    except requests.exceptions.Timeout:
        return [], "Timeout WPScan API (core)"
    except Exception as e:
        return [], f"Error WPScan API (core): {e}"

    if r.status_code == 200:
        try:
            data = r.json()
        except Exception:
            return [], "JSON inválido de WPScan API (core)"

        results = []
                                                                                           
        core_data = data.get(version_key, data)
        vuln_list = core_data.get("vulnerabilities", [])

        for entry in vuln_list:
            fixed_in = entry.get("fixed_in")
            if wp_version and fixed_in:
                try:
                    if not _version_lt(wp_version, fixed_in):
                        continue
                except Exception as _e:
                    log.debug("core: %s", _e)

            refs  = entry.get("references", {})
            cves  = refs.get("cve", [])
            sev_raw = entry.get("severity") or entry.get("cvss", {}).get("severity", "medium")
            severity = WPSCAN_SEV_MAP.get(str(sev_raw).lower(), Severity.MEDIUM)
            cvss_score = None
            if entry.get("cvss"):
                cvss_score = entry["cvss"].get("score")

            results.append(Vulnerability(
                plugin_slug="wordpress-core",
                plugin_version=wp_version,
                cve_id=f"CVE-{cves[0]}" if cves else None,
                title=entry.get("title", "Vulnerabilidad WordPress core"),
                severity=severity,
                cvss_score=cvss_score,
                fixed_in=fixed_in,
                references=refs.get("url", []),
                description=(
                    f"WordPress core v{wp_version} vulnerable. "
                    f"{'Actualizar a v' + fixed_in if fixed_in else 'Sin versión de corrección publicada.'}"
                ),
                type="wordpress",
            ))

        log.info("WPScan API [core] v%s → %d vulns", wp_version, len(results))
        return results, ""

    elif r.status_code == 401:
        return [], "Token WPScan inválido (401)"
    elif r.status_code == 404:
        log.debug("WPScan API: core v%s no encontrado (404)", wp_version)
        return [], ""
    elif r.status_code == 429:
        return [], "Rate limit WPScan API (429)"
    else:
        return [], f"WPScan API core HTTP {r.status_code}"


                                                                               
                                      
                                                                               

OFFLINE_VULNS: dict[str, list[dict]] = {
    "contact-form-7":    [
        {"affects_lt": "5.9.0",   "title": "CF7 < 5.9.0 — CSRF en carga de archivos",         "severity": "high",     "cvss": 7.5,  "cve": "CVE-2023-6449",   "fixed_in": "5.9.0"},
        {"affects_lt": "5.8.4",   "title": "CF7 < 5.8.4 — XSS reflejado en parámetros GET",   "severity": "medium",   "cvss": 6.1,  "cve": "CVE-2023-1227",   "fixed_in": "5.8.4"},
    ],
    "wpforms-lite":      [
        {"affects_lt": "1.8.7",   "title": "WPForms < 1.8.7 — XSS almacenado sin autenticación",       "severity": "high",     "cvss": 7.2,  "cve": "CVE-2024-1786",   "fixed_in": "1.8.7"},
        {"affects_lt": "1.8.4",   "title": "WPForms < 1.8.4 — IDOR en envíos de formulario",           "severity": "medium",   "cvss": 5.4,  "cve": "CVE-2023-4274",   "fixed_in": "1.8.4"},
    ],
    "ninja-forms":       [
        {"affects_lt": "3.6.26",  "title": "Ninja Forms < 3.6.26 — XSS almacenado via email",          "severity": "high",     "cvss": 7.6,  "cve": "CVE-2023-37979",  "fixed_in": "3.6.26"},
        {"affects_lt": "3.6.10",  "title": "Ninja Forms < 3.6.10 — RCE por deserialización PHP",       "severity": "critical", "cvss": 9.8,  "cve": "CVE-2022-1781",   "fixed_in": "3.6.10"},
    ],
    "gravityforms":      [
        {"affects_lt": "2.7.3",   "title": "Gravity Forms < 2.7.3 — PHP Object Injection",             "severity": "critical", "cvss": 9.8,  "cve": "CVE-2023-28782",  "fixed_in": "2.7.3"},
    ],
    "woocommerce":       [
        {"affects_lt": "8.0.0",   "title": "WooCommerce < 8.0 — SQL Injection en productos",           "severity": "critical", "cvss": 9.8,  "cve": "CVE-2023-2986",   "fixed_in": "8.0.0"},
        {"affects_lt": "7.9.0",   "title": "WooCommerce < 7.9 — Autorización incorrecta en pedidos",   "severity": "high",     "cvss": 7.3,  "cve": "CVE-2023-1671",   "fixed_in": "7.9.0"},
    ],
    "woocommerce-payments": [
        {"affects_lt": "5.6.2",   "title": "WooPayments < 5.6.2 — Escalada privilegios sin auth",      "severity": "critical", "cvss": 10.0, "cve": "CVE-2023-28121",  "fixed_in": "5.6.2"},
    ],
    "elementor":         [
        {"affects_lt": "3.18.0",  "title": "Elementor < 3.18 — XSS almacenado via widget HTML",        "severity": "high",     "cvss": 7.2,  "cve": "CVE-2024-2091",   "fixed_in": "3.18.0"},
        {"affects_lt": "3.13.2",  "title": "Elementor < 3.13.2 — RCE por subida de SVG",               "severity": "critical", "cvss": 9.9,  "cve": "CVE-2023-2106",   "fixed_in": "3.13.2"},
    ],
    "elementor-pro":     [
        {"affects_lt": "3.11.7",  "title": "Elementor Pro < 3.11.7 — Toma de control sin autenticación","severity": "critical", "cvss": 10.0, "cve": "CVE-2023-32243",  "fixed_in": "3.11.7"},
    ],
    "divi-builder":      [
        {"affects_lt": "4.23.0",  "title": "Divi Builder < 4.23 — XSS almacenado sin autenticación",   "severity": "high",     "cvss": 7.2,  "cve": "CVE-2024-3413",   "fixed_in": "4.23.0"},
    ],
    "wordpress-seo":     [
        {"affects_lt": "21.9.0",  "title": "Yoast SEO < 21.9 — XSS reflejado en metabox",              "severity": "medium",   "cvss": 5.4,  "cve": "CVE-2024-1386",   "fixed_in": "21.9.0"},
    ],
    "all-in-one-seo-pack": [
        {"affects_lt": "4.5.4",   "title": "AIOSEO < 4.5.4 — XSS almacenado via shortcode",            "severity": "high",     "cvss": 7.2,  "cve": "CVE-2023-6316",   "fixed_in": "4.5.4"},
        {"affects_lt": "4.2.9",   "title": "AIOSEO < 4.2.9 — SQL Injection autenticada",               "severity": "high",     "cvss": 7.7,  "cve": "CVE-2023-0585",   "fixed_in": "4.2.9"},
    ],
    "rank-math":         [
        {"affects_lt": "1.0.214", "title": "Rank Math < 1.0.214 — Escalada privilegios sin auth",      "severity": "critical", "cvss": 10.0, "cve": "CVE-2020-11514",  "fixed_in": "1.0.214"},
    ],
    "wordfence":         [
        {"affects_lt": "7.11.1",  "title": "Wordfence < 7.11.1 — Bypass de 2FA",                       "severity": "critical", "cvss": 9.8,  "cve": "CVE-2023-3172",   "fixed_in": "7.11.1"},
    ],
    "really-simple-ssl": [
                                                                                            
        {"affects_lt": "9.1.1",   "title": "Really Simple SSL < 9.1.1 — Bypass de autenticación 2FA",     "severity": "critical", "cvss": 9.8,  "cve": "CVE-2024-10924",  "fixed_in": "9.1.1"},
    ],
    "loginizer":         [
        {"affects_lt": "1.7.6",   "title": "Loginizer < 1.7.6 — SQL Injection sin autenticación",      "severity": "critical", "cvss": 9.8,  "cve": "CVE-2020-27615",  "fixed_in": "1.7.6"},
    ],
    "all-in-one-wp-security-and-firewall": [
        {"affects_lt": "5.2.6",   "title": "AIOWPS < 5.2.6 — XSS reflejado sin autenticación",         "severity": "high",     "cvss": 7.2,  "cve": "CVE-2023-5557",   "fixed_in": "5.2.6"},
    ],
    "wp-super-cache":    [
        {"affects_lt": "1.7.9",   "title": "WP Super Cache < 1.7.9 — RCE en configuración",            "severity": "critical", "cvss": 10.0, "cve": "CVE-2023-2641",   "fixed_in": "1.7.9"},
    ],
    "w3-total-cache":    [
        {"affects_lt": "2.4.0",   "title": "W3 Total Cache < 2.4.0 — SSRF sin autenticación",          "severity": "high",     "cvss": 8.6,  "cve": "CVE-2024-12365",  "fixed_in": "2.4.0"},
    ],
    "litespeed-cache":   [
        {"affects_lt": "6.3.0.1", "title": "LiteSpeed Cache < 6.3.0.1 — XSS almacenado sin auth",      "severity": "high",     "cvss": 7.2,  "cve": "CVE-2024-28000",  "fixed_in": "6.3.0.1"},
        {"affects_lt": "5.7",     "title": "LiteSpeed Cache < 5.7 — Escalada de privilegios",           "severity": "critical", "cvss": 9.8,  "cve": "CVE-2023-40000",  "fixed_in": "5.7"},
    ],
    "updraftplus":       [
        {"affects_lt": "1.23.10", "title": "UpdraftPlus < 1.23.10 — Backups sin autenticación",        "severity": "critical", "cvss": 9.6,  "cve": "CVE-2023-32960",  "fixed_in": "1.23.10"},
    ],
    "backwpup":          [
        {"affects_lt": "4.0.2",   "title": "BackWPup < 4.0.2 — Path Traversal en backups",             "severity": "high",     "cvss": 8.3,  "cve": "CVE-2022-4225",   "fixed_in": "4.0.2"},
    ],
    "nextgen-gallery":   [
        {"affects_lt": "3.37",    "title": "NextGEN Gallery < 3.37 — SQL Injection autenticada",        "severity": "high",     "cvss": 7.7,  "cve": "CVE-2023-3154",   "fixed_in": "3.37"},
    ],
    "revslider":         [
        {"affects_lt": "6.6.12",  "title": "Revolution Slider < 6.6.12 — LFI",                         "severity": "high",     "cvss": 7.5,  "cve": "CVE-2023-1874",   "fixed_in": "6.6.12"},
    ],
    "jetpack":           [
        {"affects_lt": "13.2.0",  "title": "Jetpack < 13.2 — Inyección código en shortcodes",          "severity": "high",     "cvss": 8.8,  "cve": "CVE-2024-2010",   "fixed_in": "13.2.0"},
        {"affects_lt": "12.1.1",  "title": "Jetpack < 12.1.1 — Path Traversal en Carousel",            "severity": "high",     "cvss": 7.5,  "cve": "CVE-2023-2996",   "fixed_in": "12.1.1"},
    ],
    "social-warfare":    [
        {"affects_lt": "3.5.3",   "title": "Social Warfare < 3.5.3 — RCE sin autenticación",           "severity": "critical", "cvss": 9.8,  "cve": "CVE-2019-9978",   "fixed_in": "3.5.3"},
    ],
    "ultimate-member":   [
        {"affects_lt": "2.6.7",   "title": "Ultimate Member < 2.6.7 — Escalada privilegios sin auth",  "severity": "critical", "cvss": 10.0, "cve": "CVE-2023-3460",   "fixed_in": "2.6.7"},
    ],
    "memberpress":       [
        {"affects_lt": "1.11.26", "title": "MemberPress < 1.11.26 — SQL Injection autenticada",        "severity": "high",     "cvss": 7.7,  "cve": "CVE-2023-5940",   "fixed_in": "1.11.26"},
    ],
    "the-events-calendar": [
        {"affects_lt": "6.2.8",   "title": "The Events Calendar < 6.2.8 — SQL Injection sin auth",     "severity": "critical", "cvss": 9.8,  "cve": "CVE-2024-2961",   "fixed_in": "6.2.8"},
    ],
    "advanced-custom-fields": [
        {"affects_lt": "6.2.5",   "title": "ACF < 6.2.5 — XSS reflejado sin autenticación",            "severity": "high",     "cvss": 7.2,  "cve": "CVE-2023-40680",  "fixed_in": "6.2.5"},
    ],
    "wp-mail-smtp":      [
        {"affects_lt": "3.8.0",   "title": "WP Mail SMTP < 3.8.0 — Exposición credenciales SMTP",      "severity": "high",     "cvss": 7.5,  "cve": "CVE-2023-2253",   "fixed_in": "3.8.0"},
    ],
    "popup-builder":     [
        {"affects_lt": "4.2.3",   "title": "Popup Builder < 4.2.3 — Inyección código sin auth",        "severity": "critical", "cvss": 9.8,  "cve": "CVE-2023-6000",   "fixed_in": "4.2.3"},
    ],
    "wpml":              [
        {"affects_lt": "4.6.9",   "title": "WPML < 4.6.9 — SSRF en importación de traducciones",       "severity": "high",     "cvss": 7.7,  "cve": "CVE-2024-6386",   "fixed_in": "4.6.9"},
    ],
    "akismet":           [
        {"affects_lt": "5.3.0",   "title": "Akismet < 5.3 — SSRF en verificación de comentarios",      "severity": "medium",   "cvss": 5.3,  "cve": "CVE-2023-6808",   "fixed_in": "5.3.0"},
    ],
    "wp-optimize":       [
        {"affects_lt": "3.2.14",  "title": "WP-Optimize < 3.2.14 — XSS reflejado sin auth",            "severity": "medium",   "cvss": 6.1,  "cve": "CVE-2023-5765",   "fixed_in": "3.2.14"},
    ],
    "cookie-law-info":   [
        {"affects_lt": "2.2.0",   "title": "CookieYes GDPR < 2.2.0 — XSS almacenado",                 "severity": "medium",   "cvss": 6.4,  "cve": "CVE-2023-6550",   "fixed_in": "2.2.0"},
    ],
    "beaver-builder-lite-version": [
        {"affects_lt": "2.7.2",   "title": "Beaver Builder < 2.7.2 — XSS almacenado",                 "severity": "medium",   "cvss": 6.4,  "cve": "CVE-2024-1698",   "fixed_in": "2.7.2"},
    ],
    "tablepress":        [
        {"affects_lt": "2.2.3",   "title": "TablePress < 2.2.3 — XSS almacenado por editor",           "severity": "medium",   "cvss": 6.4,  "cve": "CVE-2024-1079",   "fixed_in": "2.2.3"},
    ],
    "polylang":          [
        {"affects_lt": "3.5.0",   "title": "Polylang < 3.5.0 — XSS reflejado en selector idioma",      "severity": "medium",   "cvss": 6.1,  "cve": "CVE-2023-2249",   "fixed_in": "3.5.0"},
    ],
    "imagify":           [
        {"affects_lt": "2.1.2",   "title": "Imagify < 2.1.2 — CSRF en ajustes del plugin",             "severity": "medium",   "cvss": 5.4,  "cve": "CVE-2023-4278",   "fixed_in": "2.1.2"},
    ],
    "yoast-seo":         [
        {"affects_lt": "21.9.0",  "title": "Yoast SEO < 21.9 — XSS reflejado en metabox",              "severity": "medium",   "cvss": 5.4,  "cve": "CVE-2024-1386",   "fixed_in": "21.9.0"},
    ],
}

WP_CORE_VULNS: list[dict] = [
    {"affects_lt": "6.4.3", "title": "WordPress < 6.4.3 — XSS en bloques Gutenberg",          "severity": "high",     "cvss": 7.2,  "cve": "CVE-2024-24996"},
    {"affects_lt": "6.4.2", "title": "WordPress < 6.4.2 — RCE vía POP chain",                  "severity": "critical", "cvss": 9.8,  "cve": "CVE-2023-56764"},
    {"affects_lt": "6.3.2", "title": "WordPress < 6.3.2 — XSS almacenado en comentarios",      "severity": "high",     "cvss": 7.5,  "cve": "CVE-2023-5561"},
    {"affects_lt": "6.2.1", "title": "WordPress < 6.2.1 — Directory traversal en temas",        "severity": "high",     "cvss": 7.5,  "cve": "CVE-2023-2745"},
    {"affects_lt": "6.0.3", "title": "WordPress < 6.0.3 — XSS en búsqueda",                    "severity": "medium",   "cvss": 6.1,  "cve": "CVE-2022-43497"},
    {"affects_lt": "5.8.1", "title": "WordPress < 5.8.1 — SQL Injection en motor de búsqueda", "severity": "critical", "cvss": 9.8,  "cve": "CVE-2021-39203"},
]


def check_vulns_offline(plugin: PluginInfo) -> list[Vulnerability]:
    results = []
    for entry in OFFLINE_VULNS.get(plugin.slug, []):
        if plugin.version is None or _version_lt(plugin.version, entry["affects_lt"]):
            results.append(Vulnerability(
                plugin_slug=plugin.slug, plugin_version=plugin.version,
                cve_id=entry.get("cve"), title=entry["title"],
                severity=Severity(entry["severity"]), cvss_score=entry.get("cvss"),
                fixed_in=entry.get("fixed_in"),
                references=[f"https://nvd.nist.gov/vuln/detail/{entry['cve']}"] if entry.get("cve") else [],
                description=(f"Versión instalada: {plugin.version or 'desconocida'}. "
                             f"Actualizar a v{entry.get('fixed_in', 'última versión')}."),
                type=plugin.type,
            ))
    return results


def check_wp_core_vulns_offline(wp_version: str) -> list[Vulnerability]:
    results = []
    for entry in WP_CORE_VULNS:
        if _version_lt(wp_version, entry["affects_lt"]):
            results.append(Vulnerability(
                plugin_slug="wordpress-core", plugin_version=wp_version,
                cve_id=entry.get("cve"), title=entry["title"],
                severity=Severity(entry["severity"]), cvss_score=entry.get("cvss"),
                fixed_in=entry["affects_lt"],
                references=[f"https://nvd.nist.gov/vuln/detail/{entry['cve']}"] if entry.get("cve") else [],
                description=(f"WordPress core v{wp_version} vulnerable. "
                             f"Actualizar a v{entry['affects_lt']} o superior."),
                type="wordpress",
            ))
    return results


def build_generic_passive_vulns(result: ScanResult) -> list[Vulnerability]:
    """Construye vulnerabilidades pasivas genéricas para targets externos o no-WP."""
    vulns: list[Vulnerability] = []

    def _add(title: str, severity: Severity, description: str, component: str, cvss: float | None = None):
        vulns.append(Vulnerability(
            plugin_slug=component,
            plugin_version=None,
            cve_id=None,
            title=title,
            severity=severity,
            cvss_score=cvss,
            fixed_in=None,
            references=[],
            description=description,
            type="infrastructure",
            source="passive",
        ))

    if result.ssl_info:
        if not result.ssl_info.valid:
            _add(
                "TLS/SSL no válido o inaccesible",
                Severity.HIGH,
                f"No se pudo validar el certificado SSL/TLS: {result.ssl_info.error or 'error desconocido'}",
                "tls",
                7.5,
            )
        elif result.ssl_info.expired:
            _add(
                "Certificado SSL expirado",
                Severity.HIGH,
                f"El certificado del objetivo está expirado (days_left={result.ssl_info.days_left}).",
                "tls",
                7.4,
            )

    stack = result.server_stack or {}
    if stack.get("php_vulnerable") and stack.get("php_version"):
        _add(
            "Versión de PHP fuera de soporte (EOL)",
            Severity.HIGH,
            f"PHP {stack.get('php_version')} detectado como fuera de soporte ({stack.get('php_eol')}).",
            "php-runtime",
            8.0,
        )

    hsts = result.hsts_analysis or {}
    if not hsts.get("present"):
        _add(
            "HSTS ausente",
            Severity.MEDIUM,
            "No se detectó Strict-Transport-Security; el sitio puede ser más susceptible a downgrade attacks.",
            "http-headers",
            5.3,
        )

    csp = result.csp_analysis or {}
    if not csp.get("present"):
        _add(
            "Content-Security-Policy ausente",
            Severity.MEDIUM,
            "No se detectó CSP; aumenta riesgo de XSS y carga de contenido malicioso.",
            "http-headers",
            5.4,
        )

    recon = result.recon or {}
    nmap = recon.get("nmap") or {}
    dangerous_ports = {21, 23, 445, 3306, 3389, 5432, 6379, 9200, 27017}
    medium_ports = {22, 25, 110, 143, 8080, 8443}
    for item in (nmap.get("ports") or [])[:30]:
        try:
            port = int(item.get("port"))
        except Exception:
            continue
        service = (item.get("service") or "unknown").strip()
        version = (item.get("version") or "").strip()
        details = f"Puerto {port}/{item.get('proto', 'tcp')} abierto ({service}{' ' + version if version else ''})."
        if port in dangerous_ports:
            _add("Servicio sensible expuesto públicamente", Severity.HIGH, details, "network-exposure", 7.1)
        elif port in medium_ports:
            _add("Superficie de ataque de red ampliada", Severity.MEDIUM, details, "network-exposure", 5.8)

    nikto = recon.get("nikto") or {}
    for finding in (nikto.get("findings") or [])[:40]:
        msg = str(finding.get("message") or "").strip()
        if not msg:
            continue
        sev = Severity.MEDIUM
        low = msg.lower()
        if any(k in low for k in ("cve-", "sql", "rce", "command injection", "traversal", "shell")):
            sev = Severity.HIGH
        _add("Hallazgo pasivo de Nikto", sev, msg[:500], "nikto")

    return vulns


                                                                               
                       
                                                                               

class WPScanner:

    def __init__(self, config: Optional[ScannerConfig] = None):
        self.config = config or ScannerConfig()

    def scan(self, target_url: str,
             progress_callback: Optional[Callable[[str, int], None]] = None,
             finding_callback: Optional[Callable[[dict], None]] = None) -> ScanResult:

        def progress(msg: str, pct: int):
            if progress_callback:
                progress_callback(msg, pct)

        def _emit_finding(v: "Vulnerability"):
            """Emite un hallazgo en tiempo real al frontend vía SSE."""
            if not finding_callback:
                return
            try:
                finding_callback({
                    "title":     v.title or "",
                    "severity":  v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                    "cve":       v.cve_id or "",
                    "cvss":      v.cvss_score,
                    "component": v.plugin_slug or "",
                    "version":   v.plugin_version or "",
                    "fixed_in":  v.fixed_in or "",
                })
            except Exception as _e:
                try:
                    log.debug("vuln to_dict append suppressed: %s", _e)
                except Exception:
                    pass

                                                       
                                                                             
                                                                           
                                                                                   
                                                                                     

        def _save_checkpoint(label: str = ""):
            try:
                _checkpoint_path_inner = f"/tmp/wpvulnscan_partial_{result.scan_id}.json"
                                                                                        
                                                                                    
                _chk_dict = result.to_dict()
                if not getattr(result, "_enriched_vulns", None):
                                                                                                  
                    _chk_dict["vulnerabilities"] = [v.to_dict() for v in result.vulnerabilities]
                _chk_dict["_checkpoint_label"] = label
                with open(_checkpoint_path_inner, "w", encoding="utf-8") as _f:
                    json.dump(_chk_dict, _f, default=str, ensure_ascii=False)
            except Exception as _ce:
                log.debug("checkpoint save error: %s", _ce)

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        parsed   = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        hostname = parsed.hostname or ""

        scan_id = hashlib.sha256(
            f"{target_url}{time.time()}".encode() + os.urandom(8)
        ).hexdigest()[:12]
        result  = ScanResult(target_url=target_url, scan_id=scan_id, started_at=time.time())
        self._result = result                                                 
        session = _make_session(self.config)

        try:
                                                                                        
            progress("Verificando accesibilidad del objetivo...", 1)
            try:
                import urllib3
                _pf_session = requests.Session()
                _pf_session.max_redirects = 3
                _pf_adapter = requests.adapters.HTTPAdapter(
                    max_retries=urllib3.util.Retry(total=0, connect=0, read=False)
                )
                _pf_session.mount("http://", _pf_adapter)
                _pf_session.mount("https://", _pf_adapter)
                _pf_session.head(base_url, timeout=5, allow_redirects=True, verify=self.config.verify_ssl)
            except requests.exceptions.ConnectionError:
                try:
                    # Algunos objetivos bloquean HEAD pero sí responden a GET.
                    _pf_session.get(base_url, timeout=8, allow_redirects=True, verify=self.config.verify_ssl)
                except Exception:
                    result.errors.append(f"El objetivo no es accesible (Connection refused). Verifica que la URL esté activa.")
                    result.finished_at = time.time()
                    return result
            except requests.exceptions.ConnectTimeout:
                try:
                    # Fallback para host con latencia alta o HEAD no soportado.
                    _pf_session.get(base_url, timeout=10, allow_redirects=True, verify=self.config.verify_ssl)
                except Exception:
                    result.errors.append(f"El objetivo no es accesible (timeout de conexión en 5s). Verifica que la URL esté activa.")
                    result.finished_at = time.time()
                    return result
            except requests.exceptions.SSLError:
                pass                                                         
            except requests.exceptions.RequestException:
                                                                                    
                pass
            finally:
                try:
                    _pf_session.close()
                except Exception:
                    pass

                                                                                
            if self.config.run_recon:
                progress("Reconocimiento pasivo: WHOIS, DNS, Nmap, Geo...", 2)
                try:
                    from scanner.recon import run_passive_recon
                    result.recon = run_passive_recon(
                        target_url, self.config,
                        run_nmap_scan=getattr(self.config, "run_nmap", True),
                        run_nikto_scan=getattr(self.config, "run_nikto", False)
                    )
                except Exception as _re:
                    log.debug("passive recon error: %s", _re)
                    result.recon = {"error": str(_re)}
            else:
                log.debug("Reconocimiento pasivo desactivado (run_recon=False)")

                                                                               
            if target_url.startswith("https://") and hostname:
                progress("Analizando certificado SSL...", 4)
                result.ssl_info = check_ssl(hostname)

                                                                               
            progress("Descargando página principal...", 8)
            try:
                resp = session.get(target_url, timeout=self.config.timeout, allow_redirects=True)
                html, resp_headers = resp.text, dict(resp.headers)
            except requests.exceptions.SSLError:
                progress("Reintentando sin verificación SSL...", 9)
                resp = requests.get(
                    target_url,
                    timeout=self.config.timeout,
                    allow_redirects=True,
                    headers=dict(session.headers),
                    verify=False,
                )
                html, resp_headers = resp.text, dict(resp.headers)
            except requests.exceptions.RequestException as e:
                result.errors.append(f"No se pudo conectar: {e}")
                result.finished_at = time.time()
                return result

            result.server_info = resp_headers.get("Server", "") or resp_headers.get("server", "")
            result.cms_info    = resp_headers.get("X-Generator", "")

                                                             
                                                                                 
                                                                              
                                                                                
            try:
                final_url = resp.url
                final_parsed = urlparse(final_url)
                final_path = final_parsed.path.rstrip("/")
                                                                         
                subdir_m = re.search(
                    r'(?:src|href)=["\'](?:https?://[^"\']+)?(/[^"\']*?)/wp-content/',
                    html[:20000], re.I
                )
                if subdir_m:
                    candidate_subdir = subdir_m.group(1).rstrip("/")
                    if candidate_subdir and candidate_subdir != "" and candidate_subdir != "/":
                        new_base = f"{final_parsed.scheme}://{final_parsed.netloc}{candidate_subdir}"
                        if new_base != base_url:
                            log.info("MEJORA #8: WP en subdirectorio detectado: %s", new_base)
                            base_url = new_base
                            result.errors.append(
                                f"ℹ️ WordPress detectado en subdirectorio: {candidate_subdir}/"
                            )
                elif final_path and final_path != "" and final_path != "/" \
                        and "/wp-content/" in html and final_path not in base_url:
                                                                                   
                    new_base = f"{final_parsed.scheme}://{final_parsed.netloc}{final_path}"
                    if new_base != base_url:
                        log.info("MEJORA #8: WP posiblemente en subdir (redirect): %s", new_base)
                        base_url = new_base
            except Exception as _e:
                log.debug("core subdir detection: %s", _e)

                                                                               
            progress("Fingerprinting de WordPress...", 14)

                                                                             
                                                                            
                                                                           
            _wp_passive = _quick_wp_fingerprint(resp_headers, html)
            if not _wp_passive:
                log.debug("quick_wp_fingerprint: sin señales pasivas de WP en %s", base_url)

            is_wp, wp_version, wp_source, php_ver = detect_wordpress(html, resp_headers)
            result.is_wordpress = is_wp
            result.php_version  = php_ver

            if not is_wp:
                result.errors.append("⚠ WordPress no confirmado — puede estar oculto o no ser WP.")

            if not wp_version:
                progress("Buscando versión en RSS y REST API...", 18)
                wp_version, wp_source = fetch_extra_sources(session, base_url, self.config)

                                                                       
            if not wp_version:
                progress("Detectando versión por assets públicos...", 20)
                asset_result = detect_version_by_assets(session, base_url, self.config)
                if asset_result:
                    wp_version, wp_source = asset_result
                    result.wp_version_hashes = wp_version

                                                        
            if wp_version and is_wp:
                confirmed = detect_version_by_hash(session, base_url, self.config, wp_version)
                if confirmed:
                    result.wp_version_hashes = confirmed
                    wp_source = f"{wp_source}+hash-verified"


            result.wp_version        = wp_version
            result.wp_version_source = wp_source

                                                                               
            if self.config.check_wp_org and wp_version:
                progress("Consultando wordpress.org (versión más reciente)...", 22)
                try:
                    latest = get_wp_latest_version(session, self.config)
                    result.wp_latest_version = latest
                    if latest and _version_lt(wp_version, latest):
                        result.wp_outdated = True
                except Exception as _e:
                    log.debug("core: %s", _e)

                                                                               
            progress("Analizando cabeceras HTTP y WAF...", 27)
            issues, ok, leaks = check_security_headers(resp_headers)
            result.headers_issues = issues
            result.headers_ok     = ok
            if leaks:
                result.errors.extend([f"ℹ️ {l}" for l in leaks])
            result.waf_detected = detect_waf(resp_headers, html)

                                                                               
            progress("Analizando fingerprints pasivos...", 34)
            try:
                from scanner.new_detections import check_passive_fingerprints
                passive = check_passive_fingerprints(
                    session, base_url, html, resp_headers, timeout=self.config.timeout
                )
                result.passive_fingerprints = passive
                                                      
                if passive.get("exposed_emails"):
                    result.exposed_emails = passive["exposed_emails"]
                                                                                    
                for f in passive.get("findings", []):
                    if f.get("severity") in ("critical", "high"):
                        result.errors.append(f"⚠ Pasivo: {f['issue']}")
                if passive.get("pingback_url"):
                    result.pingback_url = passive["pingback_url"]
            except Exception as _pe:
                log.debug("passive fingerprints: %s", _pe)

                                                                               
            progress("Analizando contenido, scripts externos y stack...", 32)
            try:
                set_cookie_list = list(resp.headers.getlist("Set-Cookie")) if hasattr(resp.headers, "getlist") else []
            except Exception:
                set_cookie_list = []
            if not set_cookie_list:
                sc_raw = resp_headers.get("Set-Cookie", "")
                if sc_raw:
                    set_cookie_list = [sc_raw]

            def _do_malware():
                return detect_malware(html, base_url)

            def _do_js_threats():
                try:
                    return detect_external_js_threats(session, html, base_url, self.config)
                except Exception as e:
                    log.warning("Error en detección JS externa: %s", e)
                    return []

            def _do_stack():
                return fingerprint_server_stack(resp_headers, html[:30000], cookies=set_cookie_list)

            with ThreadPoolExecutor(max_workers=3) as _cex:
                _f_malware = _cex.submit(_do_malware)
                _f_js      = _cex.submit(_do_js_threats)
                _f_stack   = _cex.submit(_do_stack)
                result.malware_indicators = _f_malware.result()
                result.js_threats         = _f_js.result()
                result.server_stack       = _f_stack.result()

            if result.server_stack.get("php_version") and not result.php_version:
                result.php_version = result.server_stack["php_version"]

                                                                                   
            csp_val = (resp_headers.get("Content-Security-Policy", "")
                       or resp_headers.get("content-security-policy", ""))
            if csp_val:
                result.csp_analysis = analyze_csp(csp_val)
            else:
                result.csp_analysis = {"present": False, "issues": ["CSP ausente"], "score": 0}

            hsts_val = (resp_headers.get("Strict-Transport-Security", "")
                        or resp_headers.get("strict-transport-security", ""))
            if hsts_val:
                result.hsts_analysis = analyze_hsts(hsts_val)
            else:
                result.hsts_analysis = {"present": False, "issues": ["HSTS ausente"]}

            if set_cookie_list:
                result.cookie_issues = analyze_cookies(set_cookie_list)


                                                                               
            progress("Detectando plugins en HTML y REST API...", 37)

                                                                           
            _cached_plugins = _module_cache.get(base_url, "plugins", self.config.module_cache_ttl)
            no_ver: list[str] = []
            if _cached_plugins is not None:
                plugins_dict = _cached_plugins
                progress("Plugins cargados desde caché de módulo.", 49)
            else:
                plugins_dict = detect_plugins_from_html(html)

                for slug, p in detect_plugins_from_rest_api(session, base_url, self.config).items():
                    if slug not in plugins_dict:
                        plugins_dict[slug] = p
                    elif p.version and not plugins_dict[slug].version:
                        plugins_dict[slug].version    = p.version
                        plugins_dict[slug].confidence = 100

                for slug, p in detect_plugins_from_wpo_json(session, base_url, self.config).items():
                    if slug not in plugins_dict:
                        plugins_dict[slug] = p

                no_ver = [s for s, p in plugins_dict.items() if not p.version]

            if no_ver:
                progress(f"Leyendo readme.txt de {len(no_ver)} plugins...", 43)
                with ThreadPoolExecutor(max_workers=self.config.max_workers) as ex:
                    for slug, ver in ex.map(
                        lambda s: (s, probe_plugin_readme(session, base_url, s, self.config)), no_ver
                    ):
                        if ver:
                            plugins_dict[slug].version = ver
                            plugins_dict[slug].detected_via += "+readme"
                            plugins_dict[slug].confidence = min(plugins_dict[slug].confidence + 8, 100)

            if self.config.check_wp_org and plugins_dict:
                progress("Verificando versiones en wordpress.org...", 49)
                                                                               
                from scanner.vulns_db import get_latest_version, update_component_cache, get_conn as _vdb_conn
                with ThreadPoolExecutor(max_workers=5) as ex:
                    for slug, latest_ver in ex.map(
                        lambda sv: (sv[0], get_plugin_latest_wporg(session, sv[0], self.config)),
                        list(plugins_dict.items())
                    ):
                        if not latest_ver:
                                                                      
                            latest_ver = get_latest_version(slug)
                        if latest_ver:
                            plugins_dict[slug].latest_version = latest_ver
                                                                      
                            try:
                                _c = _vdb_conn()
                                update_component_cache(_c, slug, plugins_dict[slug].type, latest_ver)
                                _c.commit()
                                _c.close()
                            except Exception as _e:
                                log.debug("core: %s", _e)
                            if plugins_dict[slug].version and _version_lt(plugins_dict[slug].version, latest_ver):
                                plugins_dict[slug].is_outdated = True

                                                           
            if self.config.module_cache_ttl > 0 and _cached_plugins is None:
                _module_cache.set(base_url, "plugins", plugins_dict)

            result.plugins = list(plugins_dict.values())
            _save_checkpoint("plugins-detected")
            progress(f"{len(result.plugins)} plugins detectados.", 51)

                                                                        
                                                                    
                                                                            
                                                                                       
            progress("Probando plugins populares por diccionario...", 52)
            _POPULAR_PLUGINS = [
                "woocommerce","contact-form-7","yoast-seo","wordfence","jetpack",
                "akismet","elementor","all-in-one-seo-pack","wpforms-lite","really-simple-ssl",
                "duplicate-page","classic-editor","wp-super-cache","w3-total-cache","updraftplus",
                "wordpress-seo","litespeed-cache","sucuri-scanner","ithemes-security","all-in-one-wp-migration",
                "user-role-editor","redirection","wp-mail-smtp","wp-optimize","rank-math",
                "beaver-builder-plugin-lite-version","divi-builder","visual-composer",
                "woocommerce-subscriptions","woocommerce-memberships",
                "bbpress","buddypress","events-manager","the-events-calendar",
                "easy-digital-downloads","give","learnpress","learndash",
                "mailchimp-for-wp","newsletter","sendinblue","fluentform",
                "wpml-multilingual-cms","polylang","translatepress-multilingual",
                "advanced-custom-fields","toolset-types","pods","meta-box",
                "tablepress","wpdatatables","formidable","gravity-forms",
                "wp-rocket","autoptimize","hummingbird-performance","smush",
                "cloudflare","wp-cloudflare-page-cache","wpml-string-translation",
                "sitepress-multilingual-cms","polylang-pro","wpml-media",
                "slider-revolution","soliloquy-lite","smart-slider-3","master-slider",
                "nextgen-gallery","envira-gallery","media-library-assistant","wp-smushit",
                "backup-buddy","blogvault","vaultpress","malcare-security",
                "wp-cerber","login-lockdown","loginizer","wps-hide-login",
                "two-factor","miniorange-2-factor-authentication","wp-2fa",
                "woocommerce-payments","woocommerce-stripe","paypal-for-woocommerce",
                "kliken-marketing-for-google","facebook-for-woocommerce",
                "woocommerce-product-bundles","woocommerce-composite-products",
                "yith-woocommerce-wishlist","yith-woocommerce-compare",
                "woocommerce-multilingual","woocommerce-pdf-invoices-packing-slips",
                "wp-job-manager","simple-job-board","wp-job-openings",
                "loco-translate","codestyling-localization",
                "wordpress-popup","popup-maker","optin-monster",
                "sumo","pushcrew","onesignal-free-web-push-notifications",
                "loginpress","custom-login-page-customizer","peter-settings-disable-updates",
                "disable-comments","comments-not-replied-to","delete-me",
                "short-pixel-image-optimiser","robin-image-optimizer","ewww-image-optimizer",
                "bp-better-messages","mycred","gamipress","badgeos",
                "wc-vendors","dokan-lite","wcfm-marketplace",
                "searchwp","relevanssi","elasticpress",
                "wp-sweep","wp-dbmanager","adminer",
                "query-monitor","debug-bar","log-deprecated-notices",
                "health-check","site-health-tool",
                "members","capability-manager-enhanced","groups",
                "woocommerce-gateway-stripe","stripe-payments","woo-stripe-payment",
                "woocommerce-shipment-tracking","aftership-woocommerce-tracking",
                "woo-gutenberg-products-block","woocommerce-blocks",
                "monsterinsights","google-analytics-dashboard-for-wp","ga-google-analytics",
                "pixel-your-site","facebook-pixel",
                "one-click-demo-import","envato-elements","starter-templates",
                "divi-essential","essential-addons-for-elementor","happy-elementor-addons",
                "elementor-pro","ocean-extra","astra-widgets","astra-sites",
                "generateblocks","kadence-blocks","stackable-ultimate-gutenberg-blocks",
                "wp-seopress","broken-link-checker","404-to-301",
                "simple-social-icons","social-warfare","sassy-social-share",
                "schema-app-structured-data-for-schemaorg","schema","wpsso",
                "amp","official-facebook-pixel","instagram-feed",
                "wp-sitemap-page","xml-sitemap-generator-for-google","google-sitemap-generator",
                "woo-product-feed-pro","product-feed-pro","woocommerce-google-feed-manager",
                "royal-elementor-addons","premium-addons-for-elementor","je-widgets-for-elementor",
                "advanced-ads","ad-inserter","adsanity",
                "insert-headers-and-footers","header-footer-code-manager","hf-menu",
                "maintenance","coming-soon-page","ultimate-coming-soon-page",
                "under-construction-page","woocommerce-abandoned-cart","retainful",
                "metorik-helper","woocommerce-zapier","zapier",
                "wp-crontrol","advanced-cron-manager","cron-job",
                                                                               
                "bricks","bricksbuilder","crocoblock","jetengine","jetsmartfilters",
                "wpvivid-backups","backwpup","duplicator","duplicator-pro",
                "file-manager","file-manager-advanced","wp-file-manager",
                "ninja-forms","forminator","fluent-forms","ws-form",
                "unlimited-elements-for-elementor","dynamic-visibility-for-elementor",
                "woocommerce-gateway-paypal-express-checkout","woo-paypalplus",
                "meow-gallery","meow-lightbox","modula-best-grid-gallery",
                "mailpoet","mailster","wp-mail-logging",
                "wp-statistics","koko-analytics","independent-analytics",
                "sticky-header-effects-for-elementor","sticky-elements-for-elementor",
                "contact-form-cfdb7","flamingo","cf7-honeypot",
                "reusable-blocks-extended","block-visibility","spectra",
                "ultimate-addons-for-gutenberg","otter-blocks","cwicly",
                "slim-seo","squirrly-seo","premium-seo-pack",
                "real-cookie-banner","complianz","borlabs-cookie",
                "wpvr","360-viewer","woo-variation-swatches",
                "litespeed-cache","sg-cachepress","wp-fastest-cache",
                "wp-hide-security-enhancer","hide-my-wp","all-in-one-wp-security",
                "wordfence-login-security","melapress-login-security",
                "two-factor-authentication","wp-2fa","rublon",
                "woocommerce-checkout-manager","checkout-field-editor",
                "cartflows","funnelkit-funnel-builder","thrivecart",
                "translatepress-multilingual","gtranslate","weglot",
                "wp-multilang","transposh-translation-filter",
                "woocommerce-advanced-shipping","flexible-shipping",
                "after-the-deadline","grammarly","linguix",
                "smartcrawl-seo","the-seo-framework","squirrly-seo",
                "ithemes-sync","ithemes-exchange","restrict-content",
                "memberpress","paid-memberships-pro","s2member",
                "wp-stripe","stripe","stripe-for-woocommerce",
                                                                                     
                "rank-math","revslider","divi","avada","astra",
                "gravityforms","popup-builder","ultimate-member","wpml",
                "backupbuddy","essential-addons-for-elementor-lite",
                "advanced-custom-fields-pro","profilepress","jupiter",
            ]
            known_slugs = {p.slug for p in result.plugins}
            to_probe = [s for s in _POPULAR_PLUGINS if s not in known_slugs]
            if to_probe:
                progress(f"Probando {len(to_probe)} plugins populares por diccionario...", 52)

            def _probe_plugin_exist(slug: str) -> Optional[str]:
                """HEAD a /wp-content/plugins/{slug}/ — 200 o 403 confirma existencia.
                Incluye jitter aleatorio (50-200ms) para evitar patrones detectables por WAF."""
                import random as _rnd
                time.sleep(_rnd.uniform(0.05, 0.2))                              
                try:
                    url = urljoin(base_url, f"/wp-content/plugins/{slug}/")
                    r = session.head(url, timeout=max(self.config.timeout - 2, 4),
                                     allow_redirects=False)
                    if r.status_code in (200, 403, 401):
                        return slug
                                                                      
                    if r.status_code == 405:
                        r2 = session.get(urljoin(base_url, f"/wp-content/plugins/{slug}/readme.txt"),
                                         timeout=max(self.config.timeout - 2, 4),
                                         allow_redirects=False)
                        if r2.status_code == 200 and len(r2.text) > 30:
                            return slug
                except Exception as _e:
                    log.debug("suppressed: %s", _e)
                return None

            if to_probe:
                _new_plugins_from_dict: list = []                      
                with ThreadPoolExecutor(max_workers=min(self.config.max_workers, 8)) as ex:
                    for found_slug in ex.map(_probe_plugin_exist, to_probe):
                        if found_slug and found_slug not in known_slugs:
                            known_slugs.add(found_slug)
                            ver = probe_plugin_readme(session, base_url, found_slug, self.config)
                            new_p = PluginInfo(
                                slug=found_slug, version=ver,
                                detected_via="dict-probe", confidence=85,
                            )
                            if self.config.check_wp_org:
                                latest = get_plugin_latest_wporg(session, found_slug, self.config)
                                if latest:
                                    new_p.latest_version = latest
                                    if ver and _version_lt(ver, latest):
                                        new_p.is_outdated = True
                            _new_plugins_from_dict.append(new_p)
                            log.info("MEJORA #1: plugin por diccionario: %s v%s", found_slug, ver)
                                                                                    
                result.plugins.extend(_new_plugins_from_dict)

                                                                               
            progress("Detectando temas...", 54)
            themes_dict = detect_themes_from_html(html)

            no_ver_t = [s for s, t in themes_dict.items() if not t.version]
            if no_ver_t:
                with ThreadPoolExecutor(max_workers=self.config.max_workers) as ex:
                    for slug, ver in ex.map(
                        lambda s: (s, probe_theme_style(session, base_url, s, self.config)), no_ver_t
                    ):
                        if ver:
                            themes_dict[slug].version = ver
                            themes_dict[slug].detected_via += "+style.css"

                                                                          
                                                                         
            parent_slugs_to_add: dict[str, PluginInfo] = {}
            for slug, theme in list(themes_dict.items()):
                try:
                    parent_slug = probe_theme_parent(session, base_url, slug, self.config)
                    if parent_slug and parent_slug not in themes_dict:
                                                             
                        parent_ver = probe_theme_style(session, base_url, parent_slug, self.config)
                        parent_slugs_to_add[parent_slug] = PluginInfo(
                            slug=parent_slug,
                            version=parent_ver,
                            detected_via=f"parent-of-{slug}",
                            confidence=95,
                            type="theme",
                        )
                        log.info("MEJORA #5: Child theme '%s' → parent '%s' añadido", slug, parent_slug)
                        result.errors.append(
                            f"ℹ️ Child theme detectado: '{slug}' hereda de '{parent_slug}' — "
                            f"vulnerabilidades del padre incluidas en el análisis"
                        )
                except Exception as _e:
                    log.debug("core probe_theme_parent: %s", _e)
            themes_dict.update(parent_slugs_to_add)

            if self.config.check_wp_org and themes_dict:
                with ThreadPoolExecutor(max_workers=4) as ex:
                    for slug, latest_ver in ex.map(
                        lambda sv: (sv[0], get_theme_latest_wporg(session, sv[0], self.config)),
                        list(themes_dict.items())
                    ):
                        if latest_ver:
                            themes_dict[slug].latest_version = latest_ver
                            if themes_dict[slug].version and _version_lt(themes_dict[slug].version, latest_ver):
                                themes_dict[slug].is_outdated = True

            result.themes = list(themes_dict.values())
            _save_checkpoint("themes-detected")

                                                                               
            all_items = result.plugins + result.themes
            progress(f"Comprobando vulnerabilidades en {len(all_items)} componentes...", 62)

            all_vulns: list[Vulnerability] = []

                                                                                
            progress("Consultando base de datos local de vulnerabilidades...", 64)
            from scanner.vulns_db import get_vulns_for_component, get_db_freshness

            db_info  = get_db_freshness()
            db_fresh = db_info.get("fresh", True)
            if not db_fresh:
                warn_msg = f"Base de datos de vulnerabilidades lleva {db_info.get('days_old',0)} días sin actualizar. Ejecuta update_vulns.py"
                result.errors.append(f"⚠ {warn_msg}")
                log.warning(warn_msg)

            result.db_days_old    = db_info.get("days_old", 0)
            result.db_last_update = db_info.get("last_update", "Nunca")
            result.wpscan_api_used = False

                                                                
            _sev_map = {
                "critical": Severity.CRITICAL, "high": Severity.HIGH,
                "medium":   Severity.MEDIUM,   "low":  Severity.LOW,
                "info":     Severity.INFO,
            }

            for item in all_items:
                slug    = item.slug
                version = item.version
                                                                        
                                                                      
                rows    = get_vulns_for_component(slug, version, confidence=item.confidence)
                for row in rows:
                    sev = _sev_map.get(str(row.get("severity","medium")).lower(), Severity.MEDIUM)
                    v = Vulnerability(
                        title             = row.get("title",""),
                        severity          = sev,
                        cvss_score        = row.get("cvss"),
                        cvss_vector       = row.get("cvss_vector"),
                        cve_id            = row.get("cve"),
                        plugin_slug       = slug,
                        plugin_version    = version,
                        fixed_in          = row.get("fixed_in") or row.get("affects_lt",""),
                        description       = row.get("description",""),
                        type              = item.type,
                        source            = row.get("source", "offline"),
                        epss              = row.get("epss"),
                        kev               = bool(row.get("kev", 0)),
                        version_unconfirmed = bool(row.get("version_unconfirmed", False)),
                    )
                    all_vulns.append(v)
                    _emit_finding(v)

                                                                        
                                                                         
            _wp_conf = 100 if wp_version else 0
            rows = get_vulns_for_component("wordpress", wp_version, confidence=_wp_conf)
            for row in rows:
                sev = _sev_map.get(str(row.get("severity","medium")).lower(), Severity.MEDIUM)
                unconf = bool(row.get("version_unconfirmed", False))
                desc = row.get("description","")
                if unconf:
                    desc = (desc + " ⚠ Versión WP no detectada — resultado no confirmado.").strip()
                v = Vulnerability(
                    title               = row.get("title",""),
                    severity            = sev,
                    cvss_score          = row.get("cvss"),
                    cvss_vector         = row.get("cvss_vector"),
                    cve_id              = row.get("cve"),
                    plugin_slug         = "wordpress-core",
                    plugin_version      = wp_version or "desconocida",
                    fixed_in            = row.get("fixed_in",""),
                    description         = desc,
                    type                = "wordpress",
                    source              = row.get("source", "offline"),
                    epss                = row.get("epss"),
                    kev                 = bool(row.get("kev", 0)),
                    version_unconfirmed = unconf,
                )
                all_vulns.append(v)
                _emit_finding(v)

            log.info("vulns.db: %d vulnerabilidades encontradas para este sitio", len(all_vulns))

                                                                                 
                                                                               
                                                                                
            _api_token = self.config.wpscan_api_token or ""
            if _api_token:
                progress(f"Enriqueciendo con WPScan API ({len(all_items)} componentes)...", 66)
                api_vulns: list[Vulnerability] = []
                api_errors_local: list[str] = []
                _rate_limited = False

                                                                  
                _wpscan_workers = min(self.config.max_workers, 4)
                with ThreadPoolExecutor(max_workers=_wpscan_workers) as _api_ex:
                    def _fetch_api_vulns(item: PluginInfo) -> tuple[list[Vulnerability], str]:
                        if _rate_limited:
                            return [], ""
                        return check_vulns_wpscan(session, item, _api_token, self.config)

                    for item, (vulns_api, err) in zip(
                        all_items,
                        _api_ex.map(_fetch_api_vulns, all_items)
                    ):
                        if err:
                            if "429" in err or "límite" in err.lower():
                                _rate_limited = True
                                log.warning("WPScan API rate limit — parando consultas")
                                api_errors_local.append(err)
                                break
                            elif "401" in err or "403" in err:
                                                                       
                                api_errors_local.append(err)
                                result.wpscan_api_error = err
                                break
                        elif vulns_api:
                            api_vulns.extend(vulns_api)

                                 
                if wp_version and _api_token and not _rate_limited:
                    try:
                        core_vulns, core_err = check_vulns_wpscan_core(
                            session, wp_version, _api_token, self.config
                        )
                        api_vulns.extend(core_vulns)
                        if core_err and "429" not in core_err:
                            api_errors_local.append(core_err)
                    except Exception as _ce:
                        log.warning("WPScan API core: %s", _ce)

                if api_vulns:
                    result.wpscan_api_used = True
                    log.info("WPScan API: %d vulnerabilidades adicionales obtenidas", len(api_vulns))
                    all_vulns.extend(api_vulns)
                    progress(f"WPScan API: +{len(api_vulns)} vulns adicionales", 68)
                elif not api_errors_local:
                    result.wpscan_api_used = True                                                     
                    log.info("WPScan API consultada: sin vulnerabilidades adicionales")

                if api_errors_local:
                    for ae in api_errors_local[:2]:
                        result.errors.append(f"ℹ️ WPScan API: {ae}")
            else:
                result.wpscan_api_used = False

                                                                            
                                                                         
                                                                      
                                                                              
                                         
            _seen_cve: dict[str, int] = {}                                       
            _seen_title: set[str] = set()                         
            deduped: list[Vulnerability] = []
            for v in all_vulns:
                cve_key = v.cve_id.strip().upper() if v.cve_id else None
                if cve_key:
                                                                     
                    dedup_key = f"{v.plugin_slug}::{cve_key}"
                    if dedup_key in _seen_cve:
                                                                       
                        existing = deduped[_seen_cve[dedup_key]]
                        if (v.cvss_score or 0) > (existing.cvss_score or 0):
                            existing.cvss_score = v.cvss_score
                        if v.cvss_vector and not existing.cvss_vector:
                            existing.cvss_vector = v.cvss_vector
                        if v.description and not existing.description:
                            existing.description = v.description
                        if v.fixed_in and not existing.fixed_in:
                            existing.fixed_in = v.fixed_in
                        if v.epss is not None and existing.epss is None:
                            existing.epss = v.epss
                        if v.kev:
                            existing.kev = True
                        if v.references:
                            existing.references = list(set(existing.references + v.references))
                    else:
                        _seen_cve[dedup_key] = len(deduped)
                        deduped.append(v)
                else:
                                                                        
                    title_key = f"{v.plugin_slug}::{v.title.lower().strip()}"
                    if title_key not in _seen_title:
                        _seen_title.add(title_key)
                        deduped.append(v)
            all_vulns = deduped
            log.info("vulns.db: %d vulnerabilidades tras deduplicación", len(all_vulns))

            all_vulns.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 99))
            result.vulnerabilities = all_vulns
            _save_checkpoint("vulnerabilities-found")
            progress(f"{len(all_vulns)} vulnerabilidades encontradas.", 72)

                                                                               
            progress("Verificando rutas de archivos sensibles...", 76)
            result.exposed_files = check_exposed_files(
                session, base_url, self.config, timeout_total=45
            )
            progress(f"{len(result.exposed_files)} archivos/rutas expuestos.", 85)

                                                                               
            progress("Verificando XML-RPC...", 88)
            result.xmlrpc_enabled = check_xmlrpc(session, base_url, self.config)

                                                                               
            progress("Analizando robots.txt...", 89)
            result.robots_analysis = analyze_robots_txt(session, base_url, self.config)
            if result.robots_analysis.get("warnings"):
                for w in result.robots_analysis["warnings"]:
                    result.errors.append(f"ℹ️ {w}")

                                                                               
            progress("Verificando protección de wp-admin...", 90)
            result.admin_protection = check_wp_admin_protection(session, base_url, self.config)
            if result.admin_protection.get("accessible") and not result.admin_protection.get("redirects_to_login"):
                result.errors.append("⚠ wp-admin accesible directamente (sin redirección al login)")

                                                                               
            try:
                r = session.get(urljoin(base_url, "/wp-login.php"),
                                timeout=self.config.timeout, allow_redirects=False)
                result.login_exposed = (r.status_code == 200 and "log" in r.text.lower())
            except Exception as _e:
                log.debug("core: %s", _e)

                                                                               
            progress("Probando enumeración de usuarios...", 93)
            result.users = enumerate_users(session, base_url, self.config)
            _save_checkpoint("users-enumerated")

                                                                               
                                                                            
                                                                                   
            try:
                from scanner.new_detections import (
                    check_cors_misconfiguration, detect_wp_debug,
                    check_tls_full, detect_custom_login_url,
                    check_wp_cron_abuse, detect_multisite,
                    check_rest_api_auth, check_redirect_chains,
                    detect_plugins_by_timing, test_post_injections,
                    scan_backup_files, analyze_js_dependencies,
                    enumerate_users_advanced, check_login_protection,
                )
                from scanner.integrity import check_wp_core_integrity
                from scanner.active import HIDDEN_PLUGINS_PROBE as TP_PROBE

                progress("Análisis avanzado en paralelo (CORS, TLS, integridad, users…)", 94)

                                                                                
                _mt = min(self.config.timeout, 8)
                _html_content = getattr(result, "_raw_html", "")
                known_slugs = {p.slug for p in result.plugins}
                timing_candidates = [s for s in TP_PROBE if s not in known_slugs][:80]

                                                                                
                def _task_cors():
                    return check_cors_misconfiguration(session, base_url, _mt)
                def _task_debug():
                    return detect_wp_debug(session, base_url, _mt)
                def _task_tls():
                    return check_tls_full(session, base_url)
                def _task_login_url():
                    return detect_custom_login_url(session, base_url, _mt)
                def _task_cron():
                    return check_wp_cron_abuse(session, base_url, _mt)
                def _task_multisite():
                    return detect_multisite(session, base_url, _mt)
                def _task_rest_auth():
                    return check_rest_api_auth(session, base_url, _mt)
                def _task_redirects():
                    return check_redirect_chains(session, base_url, _mt)
                def _task_timing():
                    if timing_candidates:
                        return detect_plugins_by_timing(session, base_url,
                                                        timing_candidates, timeout=5)
                    return {}
                def _task_injections():
                    return test_post_injections(session, base_url, _mt)
                def _task_integrity():
                    return check_wp_core_integrity(session, base_url,
                                                   wp_version=result.wp_version,
                                                   timeout=_mt)
                def _task_backups():
                                                                               
                                                                    
                    already_found = {f.path for f in result.exposed_files}
                    return scan_backup_files(
                        session, base_url,
                        timeout=_mt,
                        skip_paths=already_found,
                    )
                def _task_js():
                    return analyze_js_dependencies(session, base_url,
                                                   html_content=_html_content,
                                                   timeout=_mt)
                def _task_users_adv():
                    return enumerate_users_advanced(session, base_url, timeout=_mt)
                def _task_login_prot():
                    return check_login_protection(session, base_url, timeout=_mt)

                _adv_tasks = {
                    "cors":        _task_cors,
                    "debug":       _task_debug,
                    "tls":         _task_tls,
                    "login_url":   _task_login_url,
                    "cron":        _task_cron,
                    "multisite":   _task_multisite,
                    "rest_auth":   _task_rest_auth,
                    "redirects":   _task_redirects,
                    "timing":      _task_timing,
                    "injections":  _task_injections,
                    "integrity":   _task_integrity,
                    "backups":     _task_backups,
                    "js":          _task_js,
                    "users_adv":   _task_users_adv,
                    "login_prot":  _task_login_prot,
                }

                _adv_results: dict = {}
                _adv_deadline = time.time() + 90                   
                with ThreadPoolExecutor(max_workers=8) as _adv_ex:
                    _adv_futures = {
                        _adv_ex.submit(fn): name
                        for name, fn in _adv_tasks.items()
                    }
                                                                        
                                                                               
                                                                               
                                                                                 
                    _remaining = list(_adv_futures.keys())
                    while _remaining:
                        _time_left = max(_adv_deadline - time.time(), 0)
                        if _time_left <= 0:
                                                           
                            for _f in _remaining:
                                _f.cancel()
                            log.warning(
                                "Deadline global módulos paralelos: %d tarea(s) canceladas",
                                len(_remaining)
                            )
                            break
                        try:
                            for _fut in as_completed(_remaining, timeout=min(_time_left, 10)):
                                _name = _adv_futures[_fut]
                                _remaining.remove(_fut)
                                try:
                                    _adv_results[_name] = _fut.result()
                                except Exception as _fe:
                                    log.warning("Módulo paralelo '%s': %s", _name, _fe)
                                    _adv_results[_name] = {}
                        except FuturesTimeout:
                                                                        
                            pass

                                                                                
                result.cors_issues    = _adv_results.get("cors", {})
                result.debug_mode     = _adv_results.get("debug", {})
                result.tls_analysis   = _adv_results.get("tls", {})
                result.custom_login   = _adv_results.get("login_url", {})
                result.wp_cron_abuse  = _adv_results.get("cron", {})
                result.multisite_info = _adv_results.get("multisite", {})
                result.rest_api_issues = _adv_results.get("rest_auth", {})
                result.redirect_chain  = _adv_results.get("redirects", {})
                result.timing_plugins  = _adv_results.get("timing") or []
                result.post_injections = _adv_results.get("injections", [])
                result.core_integrity  = _adv_results.get("integrity", {})
                result.backup_files    = _adv_results.get("backups", {})
                result.js_analysis     = _adv_results.get("js", {})
                result.users_advanced  = _adv_results.get("users_adv", {})
                result.login_protection = _adv_results.get("login_prot", {})

                                                                                
                if result.cors_issues.get("vulnerable"):
                    result.errors.append("⚠ CORS misconfiguration en /wp-json/ detectada")
                if result.debug_mode.get("debug_active"):
                    result.errors.append("⚠ WP_DEBUG=true detectado en producción")
                if result.tls_analysis.get("deprecated_protocol"):
                    result.errors.append(
                        "⚠ TLS deprecado activo: " +
                        ", ".join(result.tls_analysis.get("weak_protocol_list", [])))
                if result.wp_cron_abuse.get("abusable"):
                    result.errors.append(
                        "⚠ wp-cron.php accesible externamente (abusable para CPU abuse)")
                if result.multisite_info.get("is_multisite"):
                    result.errors.append("ℹ️ Instalación WordPress Multisite detectada")
                if result.rest_api_issues.get("exposes_emails"):
                    result.errors.append("⚠ REST API expone emails de usuarios sin auth")
                if result.redirect_chain.get("suspicious"):
                    result.errors.append(
                        "🚨 Redirección sospechosa detectada (posible malware SEO)")
                if result.login_protection.get("no_lockout_detected"):
                    result.errors.append(
                        "⚠ wp-login.php sin protección contra fuerza bruta")
                if result.login_protection.get("user_enum_via_login"):
                    result.errors.append(
                        "⚠ Enumeración de usuarios posible via mensajes de error en login")
                if result.post_injections:
                    result.errors.append(
                        f"⚠ {len(result.post_injections)} posibles inyecciones vía POST")
                if result.core_integrity.get("findings_count", 0) > 0:
                    result.errors.append(
                        f"⚠ Integridad WP core: "
                        f"{result.core_integrity['findings_count']} hallazgos")
                if result.backup_files.get("exposed"):
                    result.errors.append(
                        f"⚠ {len(result.backup_files['exposed'])} "
                        f"archivos sensibles/backup accesibles")
                if result.js_analysis.get("vulnerable_libs"):
                    result.errors.append(
                        f"⚠ {len(result.js_analysis['vulnerable_libs'])} "
                        f"librería(s) JS con vulnerabilidades conocidas")

                                                                                
                existing_logins = {
                    u.get("login") if isinstance(u, dict) else getattr(u, "login", None)
                    for u in result.users
                }
                for au in result.users_advanced.get("users", []):
                    if au.get("login") and au.get("login") not in existing_logins:
                        result.errors.append(
                            f"Usuario detectado vía {au.get('source')}: {au.get('login')}")

                progress("Análisis avanzado completado.", 97)

            except FuturesTimeout:
                log.warning("Timeout global en módulos paralelos (90s)")
                result.errors.append("⚠ Algunos módulos de análisis avanzado superaron el timeout")
            except Exception as _adv_e:
                log.warning("Módulos avanzados: %s", _adv_e, exc_info=True)
                result.errors.append(f"⚠ Error en módulos avanzados: {_adv_e}")

                                                                               
            try:
                from scanner.deep_scan import run_deep_scan
                progress("Deep scan: REST API, login, feeds, WooCommerce...", 98)
                deep_scan_scope_wp = bool(result.is_wordpress or getattr(self.config, "force_generic_passive", True))
                deep = run_deep_scan(
                    session, base_url,
                    html=html,
                    headers=resp_headers,
                    timeout=self.config.timeout,
                    is_wordpress=deep_scan_scope_wp,
                )
                result.deep_scan = deep

                                                         
                rest = deep.get("rest_deep", {})
                if rest.get("exposed_routes"):
                    n_exposed = len(rest["exposed_routes"])
                    result.errors.append(
                        f"⚠ REST API: {n_exposed} ruta(s) sensible(s) accesible(s) sin auth"
                    )
                for user in rest.get("users_via_rest", []):
                    login = user.get("login", "")
                    if login:
                        existing = [u.login if hasattr(u, "login") else u.get("login") for u in result.users]
                        if login not in existing:
                            result.errors.append(f"Usuario REST API: {login}")

                                
                login_sec = deep.get("login_security", {})
                if login_sec.get("username_enumerable"):
                    result.errors.append(
                        f"⚠ Username enumeration via login: {login_sec.get('enum_method', '')}"
                    )
                if not login_sec.get("rate_limit_detected") and login_sec.get("login_accessible"):
                    result.errors.append("⚠ Sin rate limiting en wp-login.php")

                                  
                feed_e = deep.get("feed_enum", {})
                if feed_e.get("author_enum_possible"):
                    users_found = feed_e.get("authors_via_redirect", [])
                    result.errors.append(
                        f"⚠ Author enumeration via ?author=N: {', '.join(users_found[:5])}"
                    )
                if feed_e.get("emails_in_feeds"):
                    result.errors.append(
                        f"ℹ️ Emails en feed RSS: {', '.join(feed_e['emails_in_feeds'][:3])}"
                    )

                             
                woo = deep.get("woocommerce", {})
                if woo.get("detected"):
                    result.errors.append(
                        "ℹ️ WooCommerce detectado"
                        + (f" v{woo['version']}" if woo.get("version") else "")
                    )
                if woo.get("api_accessible"):
                    result.errors.append("🚨 WooCommerce REST API accesible sin autenticación")

                                           
                changelog = deep.get("changelog", {})
                if changelog.get("found"):
                    result.errors.append(
                        f"ℹ️ {len(changelog['found'])} archivo(s) changelog/versión accesible(s)"
                    )

                                   
                ajax = deep.get("ajax_nopriv", {})
                if ajax.get("exposed_actions"):
                    result.errors.append(
                        f"⚠ {len(ajax['exposed_actions'])} acción(es) admin-ajax sin auth"
                    )

                               
                ping = deep.get("pingback", {})
                if ping.get("ssrf_risk"):
                    result.errors.append(
                        "🚨 pingback.ping activo en XML-RPC — riesgo SSRF/DDoS amplificado"
                    )

                                       
                app_pw = deep.get("app_passwords", {})
                if app_pw.get("feature_enabled"):
                    result.errors.append(
                        "ℹ️ Application Passwords (WP 5.6+) activo en este sitio"
                    )

                                 
                uploads = deep.get("uploads", {})
                if uploads.get("dangerous_files"):
                    crits = [f for f in uploads["dangerous_files"] if f.get("severity") == "critical"]
                    if crits:
                        result.errors.append(
                            f"🚨 {len(crits)} archivo(s) CRÍTICO(s) en /uploads/ (posibles webshells)"
                        )

                         
                staging = deep.get("staging", {})
                if staging.get("is_staging"):
                    result.errors.append(
                        "ℹ️ Entorno staging/desarrollo accesible públicamente"
                    )

                log.info("deep_scan completado: %d módulos", len(deep))
            except Exception as _deep_e:
                log.warning("Deep scan error: %s", _deep_e, exc_info=True)
                result.errors.append(f"⚠ Error en deep scan: {_deep_e}")

            progress("Correlando hallazgos pasivos genéricos...", 98)
            try:
                generic_vulns = build_generic_passive_vulns(result)
                if generic_vulns:
                    result.vulnerabilities.extend(generic_vulns)
                    result.vulnerabilities.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 99))
                    for gv in generic_vulns:
                        _emit_finding(gv)
                    log.info("Vulnerabilidades pasivas genéricas añadidas: %d", len(generic_vulns))
            except Exception as _gv_e:
                log.warning("Error correlando hallazgos pasivos genéricos: %s", _gv_e)

                                                                               
                                                                                
                                                                       
            progress("Consultando inteligencia de amenazas (CISA KEV + EPSS)...", 98)
            _ti_timeout = int(os.environ.get("THREAT_INTEL_TIMEOUT", "15"))
            _ti_success = False
            for _ti_attempt in range(2):                   
                try:
                    from scanner.threat_intel import enrich_vulnerabilities_with_threat_intel
                    vuln_dicts = [v.to_dict() for v in result.vulnerabilities]
                    enriched_vulns, intel_summary = enrich_vulnerabilities_with_threat_intel(
                        vuln_dicts, timeout=_ti_timeout
                    )
                    result.threat_intel = intel_summary
                    _kev_set = set(intel_summary.get("kev_cves", []))
                    result.exploit_available = list(_kev_set)
                    result._enriched_vulns = enriched_vulns
                    if intel_summary.get("kev_count", 0) > 0:
                        result.errors.append(
                            f"🚨 {intel_summary['kev_count']} CVE(s) en catálogo CISA KEV "
                            f"(explotados activamente en wild)"
                        )
                    if intel_summary.get("high_epss_count", 0) > 0:
                        result.errors.append(
                            f"⚡ {intel_summary['high_epss_count']} CVE(s) con alta probabilidad "
                            f"de explotación (EPSS > 50%)"
                        )
                                                                              
                    if not intel_summary.get("kev_fetched") and not intel_summary.get("epss_fetched"):
                        result.errors.append(
                            "ℹ️ Datos CISA KEV y EPSS no disponibles (sin conectividad o caché caducada) "
                            "— análisis de amenazas basado solo en CVSS"
                        )
                    elif not intel_summary.get("kev_fetched"):
                        result.errors.append("ℹ️ Catálogo CISA KEV no disponible — usando caché o sin datos")
                    elif not intel_summary.get("epss_fetched"):
                        result.errors.append("ℹ️ Datos EPSS no disponibles — análisis de probabilidad omitido")
                    log.info("Threat intel completado: KEV=%d EPSS_alto=%d",
                             intel_summary.get("kev_count", 0),
                             intel_summary.get("high_epss_count", 0))
                    _ti_success = True
                    break
                except Exception as _ti_e:
                    log.warning("Threat intel intento %d error: %s", _ti_attempt + 1, _ti_e)
                    if _ti_attempt == 0:
                        time.sleep(1)                                 
            if not _ti_success:
                result.threat_intel = {
                    "error": "No disponible tras 2 intentos",
                    "kev_fetched": False,
                    "epss_fetched": False,
                    "kev_count": 0,
                    "high_epss_count": 0,
                }
                result.errors.append("ℹ️ Inteligencia de amenazas no disponible — verifica conectividad")

                                                                                
            try:
                from scanner.compliance import map_compliance
                                                                                 
                _partial_result = {
                    "vulnerabilities": getattr(result, "_enriched_vulns",
                                               [v.to_dict() for v in result.vulnerabilities]),
                    "summary":         {
                        "critical_vulns": sum(1 for v in result.vulnerabilities
                                              if v.severity == Severity.CRITICAL),
                        "high_vulns":     sum(1 for v in result.vulnerabilities
                                              if v.severity == Severity.HIGH),
                    },
                    "ssl_info":        result.ssl_info.to_dict() if result.ssl_info else {},
                    "tls_analysis":    result.tls_analysis,
                    "headers_issues":  result.headers_issues,
                    "csp_analysis":    result.csp_analysis,
                    "hsts_analysis":   result.hsts_analysis,
                    "users":           [u.to_dict() for u in result.users],
                    "exposed_files":   [f.to_dict() for f in result.exposed_files],
                    "rest_api_issues": result.rest_api_issues,
                    "login_protection":result.login_protection,
                    "debug_mode":      result.debug_mode,
                    "cors_issues":     result.cors_issues,
                    "xmlrpc_enabled":  result.xmlrpc_enabled,
                    "reputation":      result.reputation or {},
                    "malware_indicators": result.malware_indicators,
                    "deep_scan":       result.deep_scan,
                    "threat_intel":    result.threat_intel,
                }
                result.compliance = map_compliance(_partial_result)
                log.info("Compliance mapeado: %d hallazgos en %d frameworks",
                         result.compliance.get("total_findings", 0),
                         len(result.compliance.get("by_framework", {})))
            except Exception as _comp_e:
                log.warning("Compliance mapper error: %s", _comp_e)
                result.compliance = {"error": str(_comp_e)}

            progress("Generando informe...", 99)

        except Exception as e:
            log.error("Error inesperado en escaneo: %s", e, exc_info=True)
            result.errors.append(f"Error inesperado: {e}")
        finally:
            session.close()

        result.finished_at = time.time()
                                                                       
        try:
            _cp = f"/tmp/wpvulnscan_partial_{result.scan_id}.json"
            if os.path.exists(_cp):
                os.remove(_cp)
        except Exception as _e:
            log.debug("suppressed: %s", _e)
        progress("¡Escaneo completado!", 100)
        return result

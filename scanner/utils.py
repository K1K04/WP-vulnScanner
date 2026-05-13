"""
WP VulnScanner — Utilidades compartidas
============================================
Funciones reutilizadas por varios módulos del scanner.

  - _version_lt         : comparación semántica de versiones (único punto de verdad)
  - WAF_SIGNATURES       : firmas de WAF/CDN centralizadas (pasivo + activo)
  - xml_safe             : escape de XML para uso en payloads
"""

from __future__ import annotations

import logging
import re
import xml.sax.saxutils as _sax

log = logging.getLogger("wpvulnscan.utils")


                                                                               
                                                       
                                                                              
                                                                   
                                                                               

def _normalize_version(v: str) -> str:
    """
    Normaliza versiones para que packaging.Version pueda parsearlas.
    Ejemplos: '2.3.1.1' → '2.3.1.1', '2.3-beta1' → '2.3b1',
              '2.3.1-RC2' → '2.3.1rc2', '5.0.0-alpha' → '5.0.0a0'

    FIX: rc regex anterior eliminaba la 'r' del output (producía 'c2' en vez de 'rc2').
    FIX: alpha sin número devolvía 'a1' en vez de 'a0'.
    """
    v = str(v).strip().lower()
                         
    v = re.sub(r'^v', '', v)
                                                           
                                                                                           
    v = re.sub(r'[-_]rc(\d*)',    lambda m: f"rc{m.group(1) or '1'}", v)
    v = re.sub(r'[-_]beta(\d*)',  lambda m: f"b{m.group(1) or '1'}",  v)
    v = re.sub(r'[-_]alpha(\d*)', lambda m: f"a{m.group(1) or '0'}",  v)                   
    v = re.sub(r'[-_]dev(\d*)',   lambda m: f".dev{m.group(1) or '0'}", v)
                                                                                       
                                                                                 
    v = re.sub(r'[^0-9a-z.+]', '', v)
                                           
    v = re.sub(r'\.{2,}', '.', v)
    v = v.strip('.')
                                                                   
    return v if any(c.isdigit() for c in v) else "0"


def _version_lt(v1: str, v2: str) -> bool:
    """
    Compara versiones semánticas. Devuelve True si v1 < v2.

    MEJORA #1: maneja correctamente edge cases que el fallback numérico
    anterior no contemplaba:
      - Versiones con 4 segmentos: 2.3.1.1 < 2.3.1.2  ✓
      - Pre-releases: 2.3.1-beta < 2.3.1  ✓
      - RC: 5.0-RC1 < 5.0  ✓
      - Prefijo v: v1.2.3  ✓
      - Versiones sin puntos: '6' < '7'  ✓
    """
    if not v1 or not v2:
        return False

                                                                      
                                                                         
    def _has_digits(s: str) -> bool:
        return any(c.isdigit() for c in str(s))

    if not _has_digits(v1) or not _has_digits(v2):
        return False

                                                     
    try:
        from packaging.version import Version, InvalidVersion
        try:
            return Version(_normalize_version(v1)) < Version(_normalize_version(v2))
        except InvalidVersion:
            pass
    except ImportError:
        pass

                                                                      
    def _parts(v: str) -> list[int]:
                                                                             
        base = re.split(r'[-_a-zA-Z]', re.sub(r'^v', '', str(v)))[0]
        segments = [x for x in base.split('.') if x.isdigit()]
                                                                            
        if not segments:
            return []
        return [int(x) for x in segments]

    def _is_prerelease(v: str) -> bool:
        return bool(re.search(r'[-_](alpha|beta|rc|dev|b\d|a\d)', str(v).lower()))

    try:
        a_parts, b_parts = _parts(v1), _parts(v2)
                                                                                               
        if not a_parts or not b_parts:
            return False
                                  
        max_len = max(len(a_parts), len(b_parts))
        a_parts += [0] * (max_len - len(a_parts))
        b_parts += [0] * (max_len - len(b_parts))

        for x, y in zip(a_parts, b_parts):
            if x < y: return True
            if x > y: return False

                                                                       
        if a_parts == b_parts:
            a_pre = _is_prerelease(v1)
            b_pre = _is_prerelease(v2)
            if a_pre and not b_pre: return True                   
            if not a_pre and b_pre: return False                  

        return False
    except Exception:
        return False


                                                                               
                                                        
                                                                        
                                                             
                                                                               

def xml_safe(value: str) -> str:
    """
    Escapa caracteres especiales XML: &, <, >, ', ".
    Usar siempre al interpolar datos de usuario en payloads XML.
    """
    return _sax.escape(str(value), {"'": "&apos;", '"': "&quot;"})


                                                                               
                                                 
                                                                     
                                                                        
                                                      
                                                                               

WAF_SIGNATURES: dict[str, list] = {
    "Cloudflare": [
        ("header", "cf-ray"),
        ("header", "cf-cache-status"),
        ("header", "cf-request-id"),
        ("header", "server", "cloudflare"),
        ("body",   "__cf_bm"),
        ("body",   "cdn-cgi/"),
        ("cookie", "cf-"),
        ("cookie", "__cfduid"),
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
        ("header", "x-wf-"),
    ],
    "ModSecurity": [
        ("body",   "ModSecurity"),
        ("body",   "mod_security"),
        ("body",   "NOYB"),
        ("header", "server", "mod_security"),
    ],
    "Imunify360": [
        ("body",   "Imunify360"),
        ("header", "x-imunify360-blocked"),
    ],
    "Barracuda WAF": [
        ("header", "x-b-waf"),
        ("body",   "Barracuda Networks"),
        ("cookie", "barracuda_"),
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
    "Imperva / Incapsula": [
        ("header", "x-iinfo"),
        ("body",   "imperva"),
        ("body",   "incapsula"),
        ("cookie", "visid_incap_"),
        ("cookie", "incap_ses_"),
    ],
    "SiteGround": [
        ("header", "x-sg-id"),
    ],
    "Varnish Cache": [
        ("header", "x-varnish"),
        ("header", "via", "varnish"),
    ],
    "Nginx + naxsi": [
        ("body",   "NAXSI_FMT"),
    ],
    "SiteLock": [
        ("body",   "sitelock"),
        ("header", "x-fw-"),
    ],
}


def detect_waf_from_response(headers: dict, body: str,
                              cookies_str: str = "") -> list[str]:
    """
    Detecta WAFs/CDNs activos a partir de cabeceras, cuerpo y cookies.
    Devuelve lista de nombres deduplicada preservando orden.
    Usada tanto por el scanner pasivo (core.py) como por el activo (active.py).
    """
    hl         = {k.lower(): v.lower() for k, v in headers.items()}
    body_lower = body[:30000].lower()
    cookies_l  = cookies_str.lower()
    detected   = []

    for waf_name, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            matched = False
            sig_type = sig[0]

            if sig_type == "header":
                header_name = sig[1].lower()
                if len(sig) == 3:
                    matched = header_name in hl and sig[2].lower() in hl[header_name]
                else:
                    matched = header_name in hl
            elif sig_type == "body":
                matched = sig[1].lower() in body_lower
            elif sig_type == "cookie":
                matched = sig[1].lower() in cookies_l

            if matched:
                detected.append(waf_name)
                break                           

    return list(dict.fromkeys(detected))                                

"""
scanner/recon.py — Módulo de Reconocimiento Pasivo v1.0
=======================================================
Recopila información del objetivo SIN enviar peticiones directas al servidor WP:
  - WHOIS del dominio  (python-whois o subprocess whois)
  - Registros DNS  (A, AAAA, MX, NS, TXT, SOA)
  - Geolocalización IP  (ip-api.com — sin API key)
  - Escaneo de puertos con Nmap  (subprocess, top-20 puertos web)
  - Logs de Transparencia de Certificados  (crt.sh — sin API key)
  - ASN / BGP  (bgpview.io — sin API key)
  - Reverse DNS  (socket)
  - Shodan (opcional — requiere SHODAN_API_KEY en .env)

Todos los errores son no-fatales; cada subsección devuelve dict parcial.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import socket
import subprocess
import time
import json
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse, quote

import requests

log = logging.getLogger(__name__)

                                                                                

def _safe(fn, *args, default=None, **kwargs):
    """Ejecuta fn(*args) y devuelve default si lanza excepción."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        log.debug("recon._safe %s: %s", fn.__name__, exc)
        return default


def _fetch_json(url: str, timeout: int = 8, headers: dict | None = None) -> dict:
    """GET JSON con timeout corto; lanza en error."""
    hdrs = {"User-Agent": "WPVulnScannerPro/1.0 (passive-recon)"}
    if headers:
        hdrs.update(headers)
    r = requests.get(url, headers=hdrs, timeout=timeout)
    r.raise_for_status()
    return r.json()


                                                                                

def run_whois(domain: str, timeout: int = 10) -> dict:
    """
    Realiza consulta WHOIS usando python-whois si está instalado;
    si no, cae al binario whois del sistema.
    """
    result: dict[str, Any] = {"domain": domain, "source": None}

                                   
    try:
        import whois as _whois                
        w = _whois.whois(domain)
        result["source"] = "python-whois"
        result["registrar"]       = _first(w.get("registrar"))
        result["creation_date"]   = _fmt_date(w.get("creation_date"))
        result["expiration_date"] = _fmt_date(w.get("expiration_date"))
        result["updated_date"]    = _fmt_date(w.get("updated_date"))
        result["name_servers"]    = _listify(w.get("name_servers"))
        result["status"]          = _listify(w.get("status"))
        result["emails"]          = _listify(w.get("emails"))
        result["org"]             = _first(w.get("org")) or _first(w.get("organization"))
        result["country"]         = _first(w.get("country"))
        result["registrant_name"] = _first(w.get("name"))
        result["dnssec"]          = str(w.get("dnssec", ""))
        result["raw"]             = str(w.text)[:3000] if hasattr(w, "text") else ""
        return result
    except ImportError:
        pass
    except Exception as exc:
        log.debug("python-whois error: %s", exc)

                             
    whois_bin = shutil.which("whois")
    if not whois_bin:
        result["error"] = "whois no disponible (instala python-whois o el paquete whois)"
        return result

    try:
        proc = subprocess.run(
            [whois_bin, domain],
            capture_output=True, text=True, timeout=timeout
        )
        raw = proc.stdout or ""
        result["source"] = "whois-cli"
        result["raw"]    = raw[:3000]

                                                
        for line in raw.splitlines():
            low = line.lower().strip()
            val = line.split(":", 1)[-1].strip() if ":" in line else ""
            if not val:
                continue
            if "registrar:" in low and not result.get("registrar"):
                result["registrar"] = val
            elif "creation date" in low or "created:" in low:
                if not result.get("creation_date"):
                    result["creation_date"] = val[:25]
            elif "expir" in low and "date" in low:
                if not result.get("expiration_date"):
                    result["expiration_date"] = val[:25]
            elif "updated date" in low or "last updated" in low:
                if not result.get("updated_date"):
                    result["updated_date"] = val[:25]
            elif "name server" in low:
                result.setdefault("name_servers", [])
                ns = val.lower().strip().rstrip(".")
                if ns and ns not in result["name_servers"]:
                    result["name_servers"].append(ns)
            elif "dnssec" in low:
                result["dnssec"] = val
            elif "registrant organization" in low or "org:" in low:
                if not result.get("org"):
                    result["org"] = val
            elif "registrant country" in low or "country:" in low:
                if not result.get("country"):
                    result["country"] = val
    except subprocess.TimeoutExpired:
        result["error"] = "Timeout en whois"
    except Exception as exc:
        result["error"] = str(exc)

    return result


def _fmt_date(val) -> str:
    if val is None:
        return ""
    if isinstance(val, list):
        val = val[0]
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d")
    return str(val)[:25]


def _first(val):
    if isinstance(val, list):
        return val[0] if val else None
    return val


def _listify(val) -> list:
    if val is None:
        return []
    if isinstance(val, (list, tuple, set)):
        return [str(v) for v in val]
    return [str(val)]


                                                                                

def run_dns(domain: str, timeout: int = 6) -> dict:
    """
    Consulta registros DNS: A, AAAA, MX, NS, TXT, SOA, CNAME.
    Usa dnspython si está disponible; si no, usa socket + dig CLI.
    """
    result: dict[str, Any] = {
        "domain": domain,
        "A": [], "AAAA": [], "MX": [], "NS": [],
        "TXT": [], "SOA": {}, "CNAME": "",
        "source": None,
    }

                            
    try:
        import dns.resolver                
        import dns.exception                

        def _resolve(rtype: str, dom: str = domain) -> list[str]:
            try:
                ans = dns.resolver.resolve(dom, rtype, lifetime=timeout)
                return [a.to_text() for a in ans]
            except Exception:
                return []

        result["source"] = "dnspython"
        result["A"]    = _resolve("A")
        result["AAAA"] = _resolve("AAAA")
        result["MX"]   = sorted(_resolve("MX"))
        result["NS"]   = sorted(_resolve("NS"))
        result["TXT"]  = _resolve("TXT")
        result["CNAME"] = (_resolve("CNAME") or [""])[0]

        try:
            soa = dns.resolver.resolve(domain, "SOA", lifetime=timeout)
            r = list(soa)[0]
            result["SOA"] = {
                "mname":   r.mname.to_text(),
                "rname":   r.rname.to_text(),
                "serial":  r.serial,
                "refresh": r.refresh,
                "retry":   r.retry,
            }
        except Exception as _e:
            try:
                log.debug("run_dns SOA lookup suppressed: %s", _e)
            except Exception:
                pass

        return result

    except ImportError:
        pass

                                                         
    result["source"] = "socket+dig"

                  
    try:
        infos = socket.getaddrinfo(domain, None)
        a_addrs = list({i[4][0] for i in infos if "." in i[4][0]})
        aaaa_addrs = list({i[4][0] for i in infos if ":" in i[4][0]})
        result["A"]    = a_addrs
        result["AAAA"] = aaaa_addrs
    except Exception as _e:
        try:
            log.debug("socket/dig resolver suppressed: %s", _e)
        except Exception:
            pass

                             
    dig_bin = shutil.which("dig")
    if dig_bin:
        for rtype in ("MX", "NS", "TXT"):
            try:
                proc = subprocess.run(
                    [dig_bin, "+short", domain, rtype],
                    capture_output=True, text=True, timeout=timeout
                )
                lines = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
                result[rtype] = lines
            except Exception as _e:
                try:
                    log.debug("dig subprocess %s lookup suppressed: %s", rtype, _e)
                except Exception:
                    pass

    return result


def _resolve_txt_records(domain: str, timeout: int = 6) -> list[str]:
    try:
        import dns.resolver

        ans = dns.resolver.resolve(domain, "TXT", lifetime=timeout)
        return [a.to_text().strip('"') for a in ans]
    except ImportError:
        pass
    except Exception as _e:
        try:
            log.debug("_resolve_txt_records: %s", _e)
        except Exception:
            pass

    dig_bin = shutil.which("dig")
    if not dig_bin:
        return []
    try:
        proc = subprocess.run(
            [dig_bin, "+short", domain, "TXT"],
            capture_output=True, text=True, timeout=timeout
        )
        lines = [l.strip().strip('"') for l in proc.stdout.splitlines() if l.strip()]
        return lines
    except Exception:
        return []


def analyze_email_security(dns_txt_records: list[str], domain: str, timeout: int = 6) -> dict:
    if not domain:
        return {
            "spf": "",
            "spf_policy": "",
            "dmarc": "",
            "dmarc_policy": "",
            "dmarc_pct": "",
            "dkim_selectors_found": [],
        }
    spf = next((r for r in dns_txt_records if "v=spf1" in r.lower()), "")
    spf_policy = ""
    if spf:
        low = spf.lower()
        if "-all" in low:
            spf_policy = "fail"
        elif "~all" in low:
            spf_policy = "softfail"
        elif "?all" in low:
            spf_policy = "neutral"
        elif "+all" in low:
            spf_policy = "pass"

    dmarc_records = _resolve_txt_records(f"_dmarc.{domain}", timeout=timeout)
    dmarc = next((r for r in dmarc_records if "v=dmarc1" in r.lower()), "")
    dmarc_policy = ""
    dmarc_pct = ""
    if dmarc:
        pol_m = re.search(r"\bp=([a-z]+)", dmarc, re.I)
        pct_m = re.search(r"\bpct=([0-9]+)", dmarc, re.I)
        if pol_m:
            dmarc_policy = pol_m.group(1).lower()
        if pct_m:
            dmarc_pct = pct_m.group(1)

    selectors = [
        "default", "google", "selector1", "selector2",
        "k1", "k2", "s1", "s2", "mail", "smtp",
    ]
    dkim_found = []
    for sel in selectors:
        records = _resolve_txt_records(f"{sel}._domainkey.{domain}", timeout=timeout)
        if any("v=dkim1" in r.lower() for r in records):
            dkim_found.append(sel)

    return {
        "spf": spf,
        "spf_policy": spf_policy,
        "dmarc": dmarc,
        "dmarc_policy": dmarc_policy,
        "dmarc_pct": dmarc_pct,
        "dkim_selectors_found": dkim_found,
    }


def run_hackertarget_hostsearch(domain: str, timeout: int = 8) -> dict:
    if not domain:
        return {"skipped": True, "reason": "Dominio no valido"}
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=timeout,
        )
        text = r.text.strip()
        if r.status_code != 200 or not text:
            return {"error": f"HTTP {r.status_code}", "raw": text[:300]}
        if "error" in text.lower():
            return {"error": text[:300]}
        subdomains = []
        ips = []
        for line in text.splitlines():
            if "," not in line:
                continue
            host, ip = line.split(",", 1)
            host = host.strip().lower()
            ip = ip.strip()
            if host and host not in subdomains:
                subdomains.append(host)
            if ip and ip not in ips:
                ips.append(ip)
        return {
            "domain": domain,
            "subdomains": subdomains[:120],
            "ips": ips[:60],
            "count": len(subdomains),
        }
    except Exception as exc:
        return {"error": str(exc)}


def generate_google_dorks(domain: str) -> list[dict]:
    if not domain:
        return []
    dorks = [
        {"dork": f"site:{domain} filetype:sql", "risk": "DB backup expuesto"},
        {"dork": f"site:{domain} filetype:log", "risk": "Logs expuestos"},
        {"dork": f"site:{domain} inurl:wp-content/uploads filetype:php", "risk": "PHP en uploads"},
        {"dork": f"site:{domain} \"index of\" wp-content", "risk": "Directory listing"},
        {"dork": f"site:{domain} \"WordPress\"", "risk": "Confirmacion CMS"},
        {"dork": f"\"{domain}\" password OR credentials site:pastebin.com", "risk": "Credenciales filtradas"},
    ]
    for d in dorks:
        d["url"] = f"https://www.google.com/search?q={quote(d['dork'])}"
    return dorks


def _extract_json_line(text: str) -> dict:
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except Exception:
            continue
    try:
        return json.loads(text)
    except Exception:
        return {}


def run_whatweb(target_url: str, timeout: int = 30) -> dict:
    whatweb_bin = shutil.which("whatweb")
    if not whatweb_bin:
        return {"skipped": True, "reason": "whatweb no instalado"}
    try:
        proc = subprocess.run(
            [whatweb_bin, "--log-json=-", "--quiet", target_url],
            capture_output=True, text=True, timeout=timeout
        )
        raw = (proc.stdout or "").strip()
        data = _extract_json_line(raw)
        plugins = []
        if isinstance(data, dict):
            plug = data.get("plugins") or {}
            if isinstance(plug, dict):
                for name, info in list(plug.items())[:80]:
                    if isinstance(info, dict):
                        versions = info.get("version") or info.get("versions") or []
                        if isinstance(versions, str):
                            versions = [versions]
                        plugins.append({
                            "name": name,
                            "version": versions[0] if versions else "",
                        })
                    else:
                        plugins.append({"name": name, "version": ""})
        return {
            "target": target_url,
            "plugins": plugins,
            "raw": raw[:2000],
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Timeout whatweb ({timeout}s)"}
    except Exception as exc:
        return {"error": str(exc)}


def run_theharvester(domain: str, sources: str = "bing,crtsh,dnsdumpster", timeout: int = 60) -> dict:
    bin_ = shutil.which("theHarvester")
    if not bin_:
        return {"skipped": True, "reason": "theHarvester no instalado"}
    if not domain:
        return {"skipped": True, "reason": "Dominio no valido"}
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="harvest_", suffix="")
    os.close(tmp_fd)
    try:
        proc = subprocess.run(
            [bin_, "-d", domain, "-b", sources, "-f", tmp_path],
            capture_output=True, text=True, timeout=timeout
        )
        json_path = tmp_path + ".json"
        data = {}
        if os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8", errors="ignore") as fh:
                try:
                    data = json.load(fh)
                except Exception:
                    data = {}
        return {
            "domain": domain,
            "emails": data.get("emails") or [],
            "hosts": data.get("hosts") or data.get("hosts_ips") or [],
            "sources": sources,
            "raw": (proc.stdout or "")[:1500],
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Timeout theHarvester ({timeout}s)"}
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        for ext in (".json", ".xml"):
            try:
                os.remove(tmp_path + ext)
            except Exception:
                pass
        try:
            os.remove(tmp_path)
        except Exception:
            pass


                                                                                

def run_geoip(ip: str, timeout: int = 6) -> dict:
    """
    Geolocalización de IP vía ip-api.com (gratuito, sin API key).
    Límite: 45 req/min desde la misma IP.
    """
    if not ip:
        return {}
    try:
        data = _fetch_json(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,"
            f"region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query",
            timeout=timeout
        )
        if data.get("status") != "success":
            return {"error": data.get("message", "ip-api error")}
        return {
            "ip":          data.get("query", ip),
            "country":     data.get("country"),
            "country_code":data.get("countryCode"),
            "region":      data.get("regionName"),
            "city":        data.get("city"),
            "lat":         data.get("lat"),
            "lon":         data.get("lon"),
            "timezone":    data.get("timezone"),
            "isp":         data.get("isp"),
            "org":         data.get("org"),
            "asn":         data.get("as"),
            "asn_name":    data.get("asname"),
        }
    except Exception as exc:
        return {"error": str(exc)}


                                                                                

                                
NMAP_PORTS = "21,22,23,25,53,80,110,143,443,445,465,587,993,995,3306,3389,5432,6379,8080,8443,8888,9200,27017"

def run_nmap(host: str, ports: str = NMAP_PORTS, timeout: int = 60) -> dict:
    """
    Escaneo de puertos con nmap (TCP SYN o TCP Connect si no hay root).
    Devuelve puertos abiertos con servicio/versión detectados.
    Requiere nmap instalado en el sistema.
    """
    result: dict[str, Any] = {"host": host, "ports": [], "raw": "", "error": None}

    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        result["error"] = "nmap no instalado (apt install nmap)"
        return result

                                                                            
                                                                             
                                                             
    scan_type = "-sS" if os.geteuid() == 0 else "-sT"

    cmd = [
        nmap_bin, scan_type, "-sV", "-Pn", "--open",
        "-T4", "-p", ports,
        "--version-intensity", "3",
        host
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        raw = proc.stdout or ""
        result["raw"] = raw[:6000]

                                
        ports_open = []
        for line in raw.splitlines():
                                                                       
            m = re.match(
                r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)",
                line.strip()
            )
            if m:
                ports_open.append({
                    "port":     int(m.group(1)),
                    "proto":    m.group(2),
                    "state":    m.group(3),
                    "service":  m.group(4),
                    "version":  m.group(5).strip(),
                })

        result["ports"] = ports_open

                               
        os_m = re.search(r"OS details: (.+)", raw)
        if os_m:
            result["os_guess"] = os_m.group(1).strip()

                  
        lat_m = re.search(r"Host is up \((.+?)\s+latency\)", raw)
        if lat_m:
            result["latency"] = lat_m.group(1)

    except subprocess.TimeoutExpired:
        result["error"] = f"Timeout ({timeout}s) — escaneo demasiado lento"
    except Exception as exc:
        result["error"] = str(exc)

    return result


def run_nikto(target_url: str, timeout: int = 180) -> dict:
    result: dict[str, Any] = {
        "target": target_url,
        "engine": "nikto",
        "findings": [],
        "summary": "",
        "raw": "",
    }

    nikto_bin = shutil.which("nikto")
    if not nikto_bin:
        return {"skipped": True, "reason": "nikto no instalado"}

    cmd = [
        nikto_bin,
        "-h", target_url,
        "-Format", "json",
        "-output", "-",
        "-nointeractive",
        "-ask", "no",
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        raw = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        result["raw"] = raw[:12000]

        json_obj = _extract_json_blob(raw)
        if json_obj:
            parsed = json.loads(json_obj)
            findings = _normalize_nikto_findings(parsed)
            result["findings"] = findings[:120]
            result["summary"] = f"Nikto detecto {len(findings)} hallazgos"
            return result

        lines = [
            ln.strip() for ln in raw.splitlines()
            if ln.strip().startswith("+") or "OSVDB" in ln or "CVE-" in ln.upper()
        ]
        result["findings"] = [{"message": ln[:300]} for ln in lines[:120]]
        result["summary"] = f"Nikto detecto {len(result['findings'])} hallazgos (modo texto)"
        return result
    except subprocess.TimeoutExpired:
        return {"error": f"Timeout nikto ({timeout}s)"}
    except Exception as exc:
        return {"error": str(exc)}


def _extract_json_blob(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return ""
    return text[start:end + 1]


def _normalize_nikto_findings(parsed: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if isinstance(parsed, dict):
        if isinstance(parsed.get("vulnerabilities"), list):
            for v in parsed["vulnerabilities"]:
                if isinstance(v, dict):
                    findings.append({
                        "id": v.get("id") or v.get("msgid") or "",
                        "uri": v.get("url") or v.get("uri") or "",
                        "message": v.get("msg") or v.get("message") or str(v)[:300],
                        "refs": v.get("references") or v.get("refs") or [],
                    })

        if isinstance(parsed.get("findings"), list):
            for v in parsed["findings"]:
                if isinstance(v, dict):
                    findings.append({
                        "id": v.get("id") or "",
                        "uri": v.get("uri") or v.get("url") or "",
                        "message": v.get("description") or v.get("msg") or str(v)[:300],
                        "refs": v.get("refs") or [],
                    })

        if not findings:
            for key in ("hosts", "results"):
                block = parsed.get(key)
                if isinstance(block, list):
                    for host_item in block:
                        if not isinstance(host_item, dict):
                            continue
                        items = host_item.get("vulnerabilities") or host_item.get("items") or []
                        if isinstance(items, list):
                            for v in items:
                                if isinstance(v, dict):
                                    findings.append({
                                        "id": v.get("id") or "",
                                        "uri": v.get("uri") or v.get("url") or "",
                                        "message": v.get("msg") or v.get("description") or str(v)[:300],
                                        "refs": v.get("references") or [],
                                    })

    return findings


def run_wayback(domain: str, timeout: int = 10) -> dict:
    if not domain:
        return {"skipped": True, "reason": "Dominio vacio"}

    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=timestamp,original,statuscode,mimetype"
        "&filter=statuscode:200&collapse=urlkey&limit=200"
    )
    try:
        data = _fetch_json(url, timeout=timeout)
        if not isinstance(data, list) or not data:
            return {"domain": domain, "snapshots": [], "count": 0}

        rows = data[1:] if isinstance(data[0], list) else data
        snapshots = []
        for row in rows[:120]:
            if isinstance(row, list) and len(row) >= 4:
                snapshots.append({
                    "timestamp": row[0],
                    "url": row[1],
                    "status": row[2],
                    "mime": row[3],
                })

        unique_hosts = sorted({urlparse(s.get("url", "")).hostname or "" for s in snapshots if s.get("url")})
        unique_hosts = [h for h in unique_hosts if h]
        return {
            "domain": domain,
            "count": len(snapshots),
            "hosts": unique_hosts[:60],
            "snapshots": snapshots,
        }
    except Exception as exc:
        return {"error": str(exc)}


                                                                               

def run_crtsh(domain: str, timeout: int = 10) -> dict:
    """
    Consulta crt.sh para obtener subdominios/SANs registrados en CT logs.
    No requiere API key.
    """
    result: dict[str, Any] = {
        "domain": domain,
        "entries": [],
        "subdomains": [],
        "source": "crt.sh",
    }

    if not domain:
        result["skipped"] = True
        result["reason"] = "Dominio no valido para consulta CT"
        return result

    urls = [
        f"https://crt.sh/?q=%25.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json",
    ]
    transient_codes = {429, 500, 502, 503, 504}
    last_error = ""

    for url in urls:
        for _ in range(2):
            try:
                resp = requests.get(
                    url,
                    timeout=timeout,
                    headers={
                        "Accept": "application/json",
                        "User-Agent": "WPVulnScannerPro/1.0 (passive-recon)",
                    },
                )

                if resp.status_code in transient_codes:
                    last_error = f"crt.sh HTTP {resp.status_code}"
                    continue

                resp.raise_for_status()
                data = resp.json()
                if not isinstance(data, list):
                    data = []

                seen: set[str] = set()
                entries: list[dict[str, Any]] = []
                for cert in data[:200]:                 
                    names = str(cert.get("name_value", "")).split("\n")
                    issuer = str(cert.get("issuer_name", ""))
                    not_before = str(cert.get("not_before", ""))[:10]
                    not_after = str(cert.get("not_after", ""))[:10]
                    for name in names:
                        name = name.strip().lstrip("*.").lower()
                        if name and name.endswith(domain.lower()) and name not in seen:
                            seen.add(name)
                            entries.append({
                                "name": name,
                                "issuer": _parse_cn(issuer),
                                "not_before": not_before,
                                "not_after": not_after,
                            })

                result["entries"] = entries[:100]
                result["subdomains"] = sorted(seen)[:80]
                result["total_certs"] = len(data)
                if last_error and (result["entries"] or result["subdomains"]):
                    result["note"] = "crt.sh recuperado tras error temporal"
                return result

            except Exception as exc:
                last_error = str(exc)

                                                                                       
    result["skipped"] = True
    result["reason"] = "Servicio CT temporalmente no disponible"
    if last_error:
        result["debug_error"] = last_error[:220]
    return result


def _parse_cn(issuer: str) -> str:
    m = re.search(r"CN=([^,]+)", issuer)
    return m.group(1).strip() if m else issuer[:60]


                                                                                

def run_asn(ip: str, timeout: int = 6) -> dict:
    """
    Información BGP/ASN vía bgpview.io (gratuito).
    """
    if not ip:
        return {}
    try:
        data = _fetch_json(f"https://api.bgpview.io/ip/{ip}", timeout=timeout)
        d = data.get("data", {})
        prefixes = d.get("prefixes", [])
        asns = []
        for p in prefixes[:5]:
            asn_info = p.get("asn", {})
            asns.append({
                "asn":         asn_info.get("asn"),
                "name":        asn_info.get("name"),
                "description": asn_info.get("description"),
                "country":     asn_info.get("country_code"),
                "prefix":      p.get("prefix"),
            })
        return {
            "ip":       ip,
            "asns":     asns,
            "rir_data": d.get("rir_allocation", {}),
        }
    except Exception as exc:
        return {"error": str(exc)}


                                                                                

def run_rdns(ip: str, timeout: int = 4) -> str:
    """PTR record para la IP dada."""
    if not ip:
        return ""
    try:
        socket.setdefaulttimeout(timeout)
        host, *_ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(None)


                                                                                 

def run_shodan(ip: str, api_key: str, timeout: int = 8) -> dict:
    """
    Consulta Shodan Host API si hay API key disponible.
    Requiere el paquete shodan (pip install shodan).

    Bugs corregidos:
      1. timeout no se pasaba a Shodan() — dejaba la conexión colgada indefinidamente
      2. ip vacío o inválido (ej. hostname sin resolver) causaba APIError sin capturar
      3. 'vulns' en Shodan puede ser una lista O un dict — se normalizaba mal
      4. 'last_update' puede ser None — slice [:10] sobre None lanzaba TypeError
      5. ScannerConfig no tiene campo shodan_api_key — siempre caía a os.environ
    """
    if not api_key:
        return {"skipped": True, "reason": "No SHODAN_API_KEY configurada"}
                                
    if not ip or not ip.strip():
        return {"skipped": True, "reason": "IP no resuelta — Shodan requiere una IP válida"}
    try:
        import shodan as _shodan                
                                                                                           
        api = _shodan.Shodan(api_key)
        api.timeout = timeout
        host = api.host(ip)
                                           
        last_update = host.get("last_update") or ""
        last_update = last_update[:10] if last_update else ""
                                                                     
        raw_vulns = host.get("vulns", {})
        if isinstance(raw_vulns, dict):
            vuln_list = list(raw_vulns.keys())[:20]
        elif isinstance(raw_vulns, list):
            vuln_list = raw_vulns[:20]
        else:
            vuln_list = []
        return {
            "ip":           ip,
            "org":          host.get("org"),
            "isp":          host.get("isp"),
            "country":      host.get("country_name"),
            "city":         host.get("city"),
            "os":           host.get("os"),
            "last_update":  last_update,
            "ports":        host.get("ports", []),
            "vulns":        vuln_list,
            "hostnames":    host.get("hostnames", []),
            "tags":         host.get("tags", []),
            "banners": [
                {
                    "port":      s.get("port"),
                    "transport": s.get("transport"),
                    "product":   s.get("product"),
                    "version":   s.get("version"),
                    "banner":    (s.get("data") or "")[:200],
                }
                for s in host.get("data", [])[:10]
            ],
        }
    except ImportError:
        return {"skipped": True, "reason": "Paquete shodan no instalado — pip install shodan"}
    except Exception as exc:
        err = str(exc)
                                                                                  
        if "404" in err or "No information available" in err:
            return {"skipped": True, "reason": f"IP {ip} sin datos en Shodan"}
        return {"error": err}


                                                                                

def run_passive_recon(
    target_url: str,
    config,                                                                             
    run_nmap_scan: bool = True,
    run_nikto_scan: bool = False,
) -> dict:
    """
    Punto de entrada principal. Ejecuta todas las subsecciones en paralelo.
    Devuelve un dict con toda la información de reconocimiento pasivo.
    """
    start = time.time()

    parsed   = urlparse(target_url)
    hostname = parsed.hostname or ""
    domain   = _strip_www(hostname)

    log.info(
        "recon pasivo iniciado para %s (nmap=%s nikto=%s)",
        domain or hostname,
        "on" if run_nmap_scan else "off",
        "on" if run_nikto_scan else "off",
    )

    result: dict[str, Any] = {
        "hostname":  hostname,
        "domain":    domain,
        "target_ip": None,
        "rdns":      "",
        "whois":     {},
        "dns":       {},
        "email_security": {},
        "geoip":     {},
        "asn":       {},
        "crtsh":     {},
        "hostsearch": {},
        "nmap":      {},
        "nikto":     {},
        "shodan":    {},
        "whatweb":   {},
        "theharvester": {},
        "google_dorks": [],
        "duration":  0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

                           
    ip = _safe(socket.gethostbyname, domain, default="")
    if not ip:
        ip = _safe(socket.gethostbyname, hostname, default="")
    result["target_ip"] = ip or None

                                  
                                                                                           
    shodan_key = ""
    try:
        shodan_key = (
            getattr(config, "shodan_api_key", "")
            or os.environ.get("SHODAN_API_KEY", "")
        )
                                                                                
        if not shodan_key:
            try:
                from scanner.api_keys import get_api_keys
                from state import DB_PATH
                keys = get_api_keys(DB_PATH)
                for k in keys:
                    if k.get("service", "").lower() == "shodan":
                        shodan_key = k.get("value_plain", "") or ""
                        break
            except Exception:
                pass
    except Exception:
        pass

                                               
    tasks = {
        "whois":  lambda: run_whois(domain),
        "dns":    lambda: run_dns(domain),
        "rdns":   lambda: run_rdns(ip) if ip else "",
        "geoip":  lambda: run_geoip(ip) if ip else {},
        "asn":    lambda: run_asn(ip) if ip else {},
        "crtsh":  lambda: run_crtsh(domain),
        "shodan": lambda: run_shodan(ip, shodan_key) if ip else {},
    }
    if getattr(config, "run_hostsearch", True):
        tasks["hostsearch"] = lambda: run_hackertarget_hostsearch(domain)
    if run_nmap_scan:
        tasks["nmap"] = lambda: run_nmap(ip or hostname)
    if run_nikto_scan:
        tasks["nikto"] = lambda: run_nikto(target_url)
    if getattr(config, "run_whatweb", False):
        tasks["whatweb"] = lambda: run_whatweb(target_url)
    if getattr(config, "run_theharvester", False):
        tasks["theharvester"] = lambda: run_theharvester(domain)

    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = {ex.submit(fn): key for key, fn in tasks.items()}
        for fut in as_completed(futures):
            key = futures[fut]
            try:
                val = fut.result(timeout=90)
                if key == "rdns":
                    result["rdns"] = val or ""
                else:
                    result[key] = val or {}
            except Exception as exc:
                log.debug("recon task '%s' error: %s", key, exc)
                result[key] = {"error": str(exc)}

    result["duration"] = round(time.time() - start, 2)
    try:
        dns_txt = (result.get("dns") or {}).get("TXT") or []
        result["email_security"] = analyze_email_security(dns_txt, domain)
    except Exception as exc:
        result["email_security"] = {"error": str(exc)}
    result["google_dorks"] = generate_google_dorks(domain)
    log.info(
        "recon pasivo completado para %s en %.2fs (ip=%s)",
        domain or hostname,
        result["duration"],
        result.get("target_ip") or "n/a",
    )
    return result


def _strip_www(hostname: str) -> str:
    """'www.example.com' → 'example.com'"""
    return re.sub(r"^www\.", "", hostname, flags=re.I)

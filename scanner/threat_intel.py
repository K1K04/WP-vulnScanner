"""
WP VulnScanner — Módulo de Inteligencia de Amenazas v1.0
=============================================================
Integra dos fuentes de datos gratuitas que ningún otro escáner WP usa:

1. EPSS (Exploit Prediction Scoring System) — FIRST.org
   Probabilidad (0-100%) de que un CVE sea explotado en los próximos 30 días.
   API: https://api.first.org/data/1.0/epss?cve=CVE-XXXX-YYYY
   Sin autenticación, sin límite de peticiones razonable.

2. CISA KEV (Known Exploited Vulnerabilities Catalog)
   Catálogo oficial del gobierno US con CVEs activamente explotados HOY.
   JSON público: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
   Se cachea localmente 24h.

Impacto en el scanner:
  - Vulnerabilidades en KEV se marcan como "ACTIVAMENTE EXPLOTADA"
  - EPSS > 0.50 añade badge "ALTA PROBABILIDAD DE EXPLOTACIÓN"
  - El risk_score sube 1.8× para vulns KEV y 1.4× para EPSS > 0.70
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import requests

log = logging.getLogger("wpvulnscan.threat_intel")

_CACHE_DIR  = Path("/tmp/wpvulnscan_cache")
_KEV_CACHE  = _CACHE_DIR / "cisa_kev.json"
_EPSS_CACHE = _CACHE_DIR / "epss_batch.json"
_KEV_URL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_URL   = "https://api.first.org/data/1.0/epss"
_CACHE_TTL  = 86400            


def _ensure_cache_dir() -> None:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _cache_valid(path: Path, ttl: int = _CACHE_TTL) -> bool:
    try:
        return path.exists() and (time.time() - path.stat().st_mtime) < ttl
    except Exception:
        return False


                                                                               
          
                                                                               

def _load_kev(timeout: int = 10) -> set[str]:
    """
    Descarga (o usa caché) el catálogo CISA KEV.
    Devuelve un set de CVE IDs actualmente explotados.
    """
    _ensure_cache_dir()

                               
    if _cache_valid(_KEV_CACHE):
        try:
            with open(_KEV_CACHE, encoding="utf-8") as f:
                data = json.load(f)
            return set(data.get("cve_ids", []))
        except Exception as _e:
            log.debug("suppressed: %s", _e)

    try:
        r = requests.get(_KEV_URL, timeout=timeout, headers={"User-Agent": "WPVulnScanner/5.8"})
        r.raise_for_status()
        data = r.json()
        vuln_list = data.get("vulnerabilities", [])
        cve_ids = [v["cveID"] for v in vuln_list if v.get("cveID")]

                                                                
        try:
            _tmp = _KEV_CACHE.with_suffix(".tmp")
            with open(_tmp, "w", encoding="utf-8") as f:                                
                json.dump({"cve_ids": cve_ids, "fetched_at": time.time()}, f)
            _tmp.replace(_KEV_CACHE)                           
        except Exception as _e:
            log.debug("suppressed: %s", _e)

        log.info("CISA KEV: %d CVEs actualmente explotados cargados", len(cve_ids))
        return set(cve_ids)

    except requests.exceptions.Timeout:
        log.warning("CISA KEV: timeout al descargar catálogo")
        return set()
    except Exception as e:
        log.warning("CISA KEV: error cargando catálogo: %s", e)
        return set()


                                                                               
      
                                                                               

def _load_epss_batch(cve_ids: list[str], timeout: int = 15) -> dict[str, float]:
    """
    Consulta EPSS para una lista de CVEs en batch.
    Devuelve dict {cve_id: epss_score (0.0-1.0)}.
    Usa caché de sesión en /tmp.
    """
    if not cve_ids:
        return {}

    _ensure_cache_dir()

                            
    cached: dict[str, float] = {}
    try:
        if _EPSS_CACHE.exists():
            with open(_EPSS_CACHE, encoding="utf-8") as f:
                cache_data = json.load(f)
                                            
            now = time.time()
            cached = {
                k: v["score"]
                for k, v in cache_data.items()
                if isinstance(v, dict) and now - v.get("ts", 0) < _CACHE_TTL
            }
    except Exception as _e:
        log.debug("suppressed: %s", _e)

                                                                                                
    to_fetch = [c for c in cve_ids if c and c not in cached][:500]
    if not to_fetch:
        return {c: cached.get(c, 0.0) for c in cve_ids if c}

                                                                    
    BATCH_SIZE = 100
    new_scores: dict[str, float] = {}

    for i in range(0, len(to_fetch), BATCH_SIZE):
        batch = to_fetch[i:i + BATCH_SIZE]
        params = [("cve", c) for c in batch]
        try:
            r = requests.get(
                _EPSS_URL, params=params, timeout=timeout,
                headers={"User-Agent": "WPVulnScanner/5.8"},
            )
            r.raise_for_status()
            data = r.json()
            for item in data.get("data", []):
                cve  = item.get("cve", "")
                epss = float(item.get("epss", 0))
                if cve:
                    new_scores[cve] = epss
        except requests.exceptions.Timeout:
            log.warning("EPSS: timeout en batch %d-%d", i, i + BATCH_SIZE)
        except Exception as e:
            log.warning("EPSS: error en batch: %s", e)

                      
    try:
        now = time.time()
                                                        
        raw_cache: dict = {}
        if _EPSS_CACHE.exists():
            with open(_EPSS_CACHE, encoding="utf-8") as f:
                raw_cache = json.load(f)
        for cve, score in new_scores.items():
            raw_cache[cve] = {"score": score, "ts": now}
        _tmp_epss = _EPSS_CACHE.with_suffix(".tmp")
        with open(_tmp_epss, "w", encoding="utf-8") as f:                                
            json.dump(raw_cache, f)
        _tmp_epss.replace(_EPSS_CACHE)                  
    except Exception as _e:
        log.debug("suppressed: %s", _e)

                             
    result = {**{c: cached[c] for c in cve_ids if c and c in cached},
              **{c: new_scores.get(c, 0.0) for c in to_fetch if c}}
    return result


                                                                               
             
                                                                               

def enrich_vulnerabilities_with_threat_intel(
    vulnerabilities: list[dict],
    timeout: int = 12,
) -> tuple[list[dict], dict]:
    """
    Enriquece una lista de vulnerabilidades (ya serializadas a dict) con:
      - kev:   True/False — está en el catálogo CISA KEV (explotada activamente)
      - epss:  float 0-1 — probabilidad EPSS de explotación en 30 días
      - epss_pct: str "12.3%" — formato legible
      - threat_label: str — etiqueta para la UI

    Devuelve (vulns_enriquecidas, intel_summary).
    intel_summary tiene:
      - kev_count: int
      - high_epss_count: int  (EPSS > 0.50)
      - kev_cves: list[str]
    """
    cve_ids = [v.get("cve_id") for v in vulnerabilities if v.get("cve_id")]

                                                       
    kev_set: set[str] = set()
    epss_map: dict[str, float] = {}

    try:
        kev_set = _load_kev(timeout=timeout)
    except Exception as e:
        log.warning("threat_intel KEV: %s", e)

    try:
        epss_map = _load_epss_batch(cve_ids, timeout=timeout)
    except Exception as e:
        log.warning("threat_intel EPSS: %s", e)

    enriched = []
    kev_cves: list[str] = []
    high_epss_count = 0

    for v in vulnerabilities:
        cve = v.get("cve_id") or ""
        in_kev = bool(cve and cve in kev_set)
        epss   = epss_map.get(cve, 0.0) if cve else 0.0

        if in_kev:
            kev_cves.append(cve)
        if epss > 0.50:
            high_epss_count += 1

                                       
        if in_kev:
            threat_label = "🚨 EXPLOTADA ACTIVAMENTE (CISA KEV)"
        elif epss > 0.70:
            threat_label = f"⚡ Alta probabilidad de explotación (EPSS {epss*100:.1f}%)"
        elif epss > 0.30:
            threat_label = f"⚠ Probabilidad moderada (EPSS {epss*100:.1f}%)"
        elif epss > 0:
            threat_label = f"EPSS {epss*100:.1f}%"
        else:
            threat_label = ""

        enriched.append({
            **v,
            "kev":          in_kev,
            "epss":         round(epss, 4),
            "epss_pct":     f"{epss*100:.1f}%",
            "threat_label": threat_label,
        })

                                                               
    def _sort_key(v):
        return (
            0 if v.get("kev") else 1,
            -(v.get("epss") or 0),
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                v.get("severity", "info"), 9
            ),
        )

    enriched.sort(key=_sort_key)

    summary = {
        "kev_count":       len(kev_cves),
        "high_epss_count": high_epss_count,
        "kev_cves":        kev_cves,
        "epss_fetched":    len(epss_map) > 0,
        "kev_fetched":     len(kev_set) > 0,
    }

    log.info(
        "Threat intel: %d vulns enriquecidas | KEV=%d | EPSS_alto=%d",
        len(enriched), len(kev_cves), high_epss_count,
    )
    return enriched, summary

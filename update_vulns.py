                      
"""
WP VulnScanner — Actualizador multi-fuente v3.0
=====================================================
FUENTES (en orden de prioridad):
  1. Wordfence Intelligence  — BD completa, gratis, sin API key, actualización diaria
  2. WPScan API              — enriquecimiento opcional (requiere token, 25 req/día free)
  3. NVD / NIST              — CVEs recientes con contexto CPE
  4. Patchstack              — especializado WP, datos estructurados
  5. GitHub Advisory DB      — GHSA con referencias cruzadas
  6. Offline seed            — datos base garantizados sin red

Wordfence Intelligence API (gratis, sin registro):
  Scanner feed completo: https://www.wordfence.com/threat-intel/vulnerabilities/production/
  Delta diario:          https://www.wordfence.com/threat-intel/vulnerabilities/production/
                         ?modified_after=<ISO-date>
  La BD cubre ~40.000 vulnerabilidades WordPress. Se actualiza cada 24h.
  Cada vuln incluye: CVSS, CVE, affected_versions exactas por plugin/tema/core.
"""
from __future__ import annotations
import argparse, json, os, re, sys, time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
import requests

sys.path.insert(0, str(Path(__file__).parent))
from scanner.vulns_db import (
    VULNS_DB_PATH, get_conn, init_vulns_db, upsert_vuln,
    update_component_cache, set_meta, get_db_stats, OFFLINE_SEED, _seed_offline,
)
try:
    from scanner.vulns_db import get_meta
except ImportError:
    def get_meta(conn, key, default=None):
        try:
            r = conn.execute("SELECT value FROM db_meta WHERE key=?", (key,)).fetchone()
            return r[0] if r else default
        except Exception:
            return default


                                                                                
class C:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[96m"
    W="\033[1m";  Z="\033[0m";  M="\033[95m"

def ok(m):   print(f"{C.G}✓{C.Z} {m}")
def warn(m): print(f"{C.Y}⚠{C.Z} {m}")
def err(m):  print(f"{C.R}✗{C.Z} {m}")
def info(m): print(f"{C.B}→{C.Z} {m}")
def head(m): print(f"\n{C.W}{m}{C.Z}")
def prog(m): print(f"\r{C.M}…{C.Z} {m}", end="", flush=True)


SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "WPVulnScanner-Updater/3.0 (github.com/wpvulnscan)",
    "Accept":     "application/json",
})

CHECKPOINT = Path(__file__).parent / ".update_checkpoint.json"

TRACKED_PLUGINS = [
    "contact-form-7","wpforms-lite","ninja-forms","gravityforms","woocommerce",
    "woocommerce-payments","elementor","elementor-pro","divi-builder","wordpress-seo",
    "yoast-seo","all-in-one-seo-pack","rank-math","wordfence","really-simple-ssl",
    "loginizer","all-in-one-wp-security-and-firewall","wp-super-cache","w3-total-cache",
    "litespeed-cache","updraftplus","backwpup","nextgen-gallery","revslider","jetpack",
    "social-warfare","ultimate-member","memberpress","the-events-calendar",
    "advanced-custom-fields","advanced-custom-fields-pro","wp-mail-smtp","popup-builder",
    "wpml","akismet","bbpress","buddypress","wpdiscuz","redirection","wp-fastest-cache",
    "autoptimize","give","wp-statistics","essential-addons-for-elementor-lite",
    "backupbuddy","profilepress","cookie-law-info","wp-optimize","tablepress",
    "polylang","imagify","beaver-builder-lite-version","wps-hide-login",
    "wp-cerber","sucuri-scanner","ithemes-security","two-factor","wp-2fa",
    "duplicator","all-in-one-wp-migration","wp-migrate-db","classic-editor",
    "bricks","file-manager","ninja-forms","memberpress","cartflows",
    "wpvivid-backups","real-cookie-banner","stripe","forminator",
]
TRACKED_THEMES = [
    "divi","avada","the7","bridge","enfold","betheme","salient","flatsome",
    "newspaper","astra","generatepress","oceanwp","storefront","hello-elementor",
    "twentytwentyfour","twentytwentythree","kadence","blocksy","neve",
]

WPSCAN_BASE = "https://wpscan.com/api/v3"

                                                                               
         
                                                                               

def _cvss_to_severity(score) -> str:
    if score is None: return "medium"
    s = float(score)
    if s >= 9.0: return "critical"
    if s >= 7.0: return "high"
    if s >= 4.0: return "medium"
    return "low"


def _extract_cve(refs, _depth: int = 0) -> Optional[str]:
    """Extrae el primer CVE-YYYY-NNNNN de una lista de referencias o strings.
    Bug 2 fix: _depth guard evita RecursionError con JSON anidado profundo.
    """
    if _depth > 8:                                                             
        return None
    if isinstance(refs, str):
        m = re.search(r'CVE-\d{4}-\d+', refs)
        return m.group(0) if m else None
    if isinstance(refs, list):
        for r in refs:
            cve = _extract_cve(r, _depth + 1)
            if cve: return cve
    if isinstance(refs, dict):
        for key in ("cve", "CVE", "identifiers"):
            val = refs.get(key)
            if val:
                cve = _extract_cve(val, _depth + 1)
                if cve: return cve
    return None


def _parse_version_range(affected_versions: dict) -> tuple[str, Optional[str]]:
    """
    Parsea el objeto affected_versions de Wordfence Intelligence.
    Formato: {"* <= 3.4.0": {"from_version":"*","to_version":"3.4.0","to_inclusive":true}}
    Devuelve (affects_lt, affects_gte).

    Bug 1 fix: procesa TODOS los rangos (antes solo el primero) y maneja
    to_inclusive:true correctamente — cuando la versión límite ES vulnerable
    (inclusive) y no hay versión parcheada conocida, añade sufijo ".99999"
    para que el comparador la incluya como vulnerable.
    Bug 6 fix: ya no hace break tras el primer rango.
    """
    affects_lt  = "0"
    affects_gte = None

    if not affected_versions or not isinstance(affected_versions, dict):
        return affects_lt, affects_gte

    best_to  = "0"
    best_gte = None

    for _, range_data in affected_versions.items():
        if not isinstance(range_data, dict):
            continue
        to_ver      = range_data.get("to_version", "")
        from_ver    = range_data.get("from_version", "*")
        to_inclusive = range_data.get("to_inclusive", False)

        if to_ver and to_ver != "*":
                                                                               
                                                                           
                                                                       
                                                                  
            adjusted = f"{to_ver}.99999" if to_inclusive else to_ver
                                                                          
            from scanner.utils import _version_lt as _vlt
            try:
                if best_to == "0" or _vlt(best_to.replace(".99999", ""), to_ver):
                    best_to = adjusted
            except Exception:
                best_to = adjusted

        if from_ver and from_ver != "*":
            from_incl = range_data.get("from_inclusive", True)
            best_gte = from_ver if from_incl else None

    if best_to != "0":
        affects_lt = best_to
    affects_gte = best_gte

    return affects_lt, affects_gte


def _patched_version(patched_versions) -> str:
    """Extrae la primera versión parcheada de la lista."""
    if not patched_versions:
        return "0"
    if isinstance(patched_versions, list) and patched_versions:
        return str(patched_versions[0]).strip()
    if isinstance(patched_versions, str):
        return patched_versions.strip()
    return "0"


                                                                               
                                                                    
                                                                               

WF_BASE = "https://www.wordfence.com/threat-intel/vulnerabilities/production/"

def source_wordfence_intelligence(conn, dry_run: bool, incremental: bool = True) -> int:
    """
    Descarga la BD completa de Wordfence Intelligence.

    Estrategia de actualización incremental:
    - Primera ejecución: descarga todo (~40.000 CVEs, ~15MB JSON)
    - Siguientes: solo modifizados en las últimas 48h usando ?modified_after=
    - Guarda ETag y Last-Modified en db_meta para cache HTTP

    Estructura de cada vuln:
    {
      "id": "8c9f...",         ← UUID propio de Wordfence
      "title": "...",
      "description": "...",
      "cvss": {"score": 8.8, "vector": "CVSS:3.1/AV:N/..."},
      "cve": "CVE-2024-1234",  ← o null
      "software": [{
        "type": "plugin",      ← plugin | theme | core
        "slug": "elementor",
        "affected_versions": {"* <= 3.18.0": {"to_version":"3.18.0","to_inclusive":true,...}},
        "patched_versions": ["3.18.1"]
      }],
      "references": ["https://..."],
      "published": "2024-01-15T10:00:00+00:00",
      "updated": "2024-01-16T08:00:00+00:00"
    }
    """
    head("Wordfence Intelligence — BD completa (gratis, sin API key)")

                                       
    last_etag     = get_meta(conn, "wf_etag", "")
    last_modified = get_meta(conn, "wf_last_modified", "")
    last_update   = get_meta(conn, "wf_last_update", "")

                                  
    use_delta = incremental and bool(last_update)
    url = WF_BASE
    params: dict = {}

    if use_delta:
        try:
            dt = datetime.fromisoformat(last_update)
                                                                         
            delta_from = (dt - timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%S")
            params["modified_after"] = delta_from
            info(f"Actualización incremental desde {delta_from}")
        except ValueError:
            use_delta = False
            info("Primera descarga completa (~15MB, puede tardar 30-60s)...")
    else:
        info("Primera descarga completa (~15MB, puede tardar 30-60s)...")

    headers = {}
    if last_etag and not use_delta:
        headers["If-None-Match"] = last_etag
    if last_modified and not use_delta:
        headers["If-Modified-Since"] = last_modified

    try:
        prog("Conectando a Wordfence Intelligence API...")
        resp = SESSION.get(url, params=params, headers=headers, timeout=60, stream=True)

        if resp.status_code == 304:
            ok("BD Wordfence sin cambios (304 Not Modified) — nada que actualizar")
            return 0

        if resp.status_code != 200:
            warn(f"Wordfence Intelligence HTTP {resp.status_code} — saltando")
            return 0

                                
        chunks = []
        downloaded = 0
        for chunk in resp.iter_content(chunk_size=65536):
            chunks.append(chunk)
            downloaded += len(chunk)
            prog(f"Descargando... {downloaded//1024}KB")

        print()                                

        raw = b"".join(chunks)
        ok(f"Descargados {len(raw)//1024}KB")

    except requests.exceptions.Timeout:
        warn("Timeout descargando Wordfence Intelligence (>60s)")
        return 0
    except Exception as e:
        warn(f"Error descargando Wordfence Intelligence: {e}")
        return 0

                  
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        warn(f"JSON inválido de Wordfence: {e}")
        return 0

                                                                  
    if isinstance(data, dict):
        vulns_raw = list(data.values())
    elif isinstance(data, list):
        vulns_raw = data
    else:
        warn(f"Formato inesperado de Wordfence: {type(data)}")
        return 0

    info(f"{len(vulns_raw):,} vulnerabilidades recibidas")

    total = 0
    skipped = 0
    batch_size = 500

    for i, item in enumerate(vulns_raw):
        if not isinstance(item, dict):
            skipped += 1
            continue

                                                                               
        software_list = item.get("software") or []
        if not software_list:
                                                   
            slug = item.get("slug") or item.get("affected_software_slug", "")
            if slug:
                software_list = [{
                    "type":              item.get("software_type", "plugin"),
                    "slug":              slug,
                    "affected_versions": item.get("affected_versions", {}),
                    "patched_versions":  [item.get("patched_in", item.get("fixed_in", "0"))],
                }]

        if not software_list:
            skipped += 1
            continue

                                                                               
        wf_id   = item.get("id", "")
        title   = str(item.get("title") or "").strip()[:200]
        desc    = str(item.get("description") or "").strip()[:500]
        updated = item.get("updated") or item.get("updated_at") or datetime.now().isoformat()

                             
        cvss_obj = item.get("cvss") or {}
        if isinstance(cvss_obj, dict):
            cvss_score  = cvss_obj.get("score")
            cvss_vector = cvss_obj.get("vector") or cvss_obj.get("cvss_vector")
        elif isinstance(cvss_obj, (int, float)):
            cvss_score  = float(cvss_obj)
            cvss_vector = None
        else:
            cvss_score  = item.get("cvss_score")
            cvss_vector = item.get("cvss_vector")

        try:
            cvss_score = float(cvss_score) if cvss_score is not None else None
        except (TypeError, ValueError):
            cvss_score = None

                                                        
        if cvss_vector and isinstance(cvss_vector, str):
            if not cvss_vector.startswith("CVSS:"):
                cvss_vector = "CVSS:3.1/" + cvss_vector
        else:
            cvss_vector = None

        severity = _cvss_to_severity(cvss_score)
                                                                         
        if not cvss_score:
            sev_raw = item.get("severity") or item.get("risk_level") or ""
            sev_map = {
                "critical":"critical", "high":"high",
                "medium":"medium",     "moderate":"medium",
                "low":"low",           "informational":"low",
            }
            severity = sev_map.get(str(sev_raw).lower(), "medium")

                                                                                           
        kev = bool(item.get("is_exploited") or item.get("exploited_in_wild") or
                   item.get("cisa_kev") or False)

             
        cve_id = item.get("cve") or item.get("cve_id")
        if not cve_id:
            cve_id = _extract_cve(item.get("references", []))
        if cve_id and not str(cve_id).startswith("CVE-"):
            cve_id = f"CVE-{cve_id}" if re.match(r"\d{4}-\d+", str(cve_id)) else None

                     
        refs = item.get("references") or []
        ref_url = ""
        if isinstance(refs, list) and refs:
            ref_url = str(refs[0])
        elif isinstance(refs, dict):
            urls = refs.get("url") or refs.get("urls") or []
            if urls: ref_url = str(urls[0])
        if cve_id and not ref_url:
            ref_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                                                                               
        for sw in software_list:
            if not isinstance(sw, dict):
                continue

            slug = (sw.get("slug") or "").strip().lower()
            if not slug:
                continue

            comp_type = str(sw.get("type") or "plugin").lower()
            if comp_type not in ("plugin", "theme", "core"):
                comp_type = "plugin"
            if slug in ("wordpress", "wordpress-core"):
                comp_type = "core"
                slug = "wordpress"

                              
            affected_versions = sw.get("affected_versions") or {}
            affects_lt, affects_gte = _parse_version_range(affected_versions)

                                                           
            patched = _patched_version(sw.get("patched_versions"))
            fixed_in = patched if patched != "0" else affects_lt

                                                               
            if fixed_in == "0" and affects_lt == "0":
                skipped += 1
                continue

                                                                    
                                                                                       
                                                                                  
                                                                                    

            vuln = {
                "component":   slug,
                "comp_type":   comp_type,
                "affects_lt":  fixed_in,
                "affects_gte": affects_gte,
                "title":       title or f"{slug} vulnerability",
                "severity":    severity,
                "cvss":        cvss_score,
                "cvss_vector": cvss_vector,
                "cve":         cve_id,
                "url":         ref_url,
                "fixed_in":    fixed_in,
                "description": desc,
                "kev":         kev,
                "source":      f"wordfence:{wf_id[:8]}" if wf_id else "wordfence",
                "updated_at":  updated,
            }

            if not dry_run:
                try:
                    upsert_vuln(conn, vuln)
                except Exception as e:
                    warn(f"  Error insertando {slug}: {e}")
                    continue

            total += 1

                         
        if not dry_run and (i + 1) % batch_size == 0:
            conn.commit()
            prog(f"Procesados {i+1:,}/{len(vulns_raw):,} ({total:,} vulns insertadas)...")

    if not dry_run:
        conn.commit()

    print()                             

                                                  
    if not dry_run:
        etag = resp.headers.get("ETag", "")
        lm   = resp.headers.get("Last-Modified", "")
        if etag:      set_meta(conn, "wf_etag", etag)
        if lm:        set_meta(conn, "wf_last_modified", lm)
        set_meta(conn, "wf_last_update", datetime.now(timezone.utc).isoformat())
        conn.commit()

    ok(f"Wordfence Intelligence: {total:,} vulns insertadas/actualizadas ({skipped} saltadas)")
    return total


                                                                               
                                                  
                                                                               

class RateLimitDailyError(Exception):
    pass


def _wpscan_get(ep: str, token: str, _retries: int = 3):
    """Bug 5 fix: retry iterativo en vez de recursivo para evitar stack overflow."""
    for attempt in range(_retries):
        try:
            r = SESSION.get(
                f"{WPSCAN_BASE}/{ep}",
                headers={"Authorization": f"Token token={token}"},
                timeout=15,
            )
            if r.status_code == 200:
                return r.json()
            if r.status_code == 401:
                err("Token WPScan inválido")
                raise ValueError("WPScan token inválido (401) — verifica WPSCAN_API_TOKEN en .env")
            if r.status_code == 429:
                                                                                  
                try:
                    secs = int(r.headers.get("Retry-After", "86400"))
                except (ValueError, TypeError):
                    secs = 86400
                if secs > 300:
                    raise RateLimitDailyError(secs)
                warn(f"Rate limit WPScan — esperando {secs}s (intento {attempt+1}/{_retries})")
                time.sleep(secs + 1)
                continue                           
            if r.status_code == 404:
                return None
            warn(f"WPScan HTTP {r.status_code} en {ep}")
            return None
        except RateLimitDailyError:
            raise
        except ValueError:
            raise
        except Exception as e:
            warn(f"WPScan error (intento {attempt+1}/{_retries}): {e}")
            if attempt < _retries - 1:
                time.sleep(2)
    return None


def _parse_wpscan_vulns(data: dict, slug: str, comp_type: str) -> list[dict]:
    raw = data.get(slug, data).get("vulnerabilities", [])
    out = []
    for entry in raw:
        fv = entry.get("fixed_in")
        if not fv:
            continue
        cf = entry.get("cvss") or {}
        if not isinstance(cf, dict):
            cf = {}
        sev_raw = str(entry.get("severity") or cf.get("severity") or "medium").lower()
        sev = {"critical": "critical", "high": "high",
               "medium": "medium", "low": "low"}.get(sev_raw, "medium")
        refs = entry.get("references", {})
        cves = refs.get("cve", [])
        out.append({
            "component":   slug,
            "comp_type":   comp_type,
            "affects_lt":  fv,
            "title":       entry.get("title", "")[:200],
            "severity":    sev,
            "cvss":        cf.get("score"),
            "cve":         f"CVE-{cves[0]}" if cves else None,
            "fixed_in":    fv,
            "source":      "wpscan",
            "updated_at":  datetime.now().isoformat(),
        })
    return out


def _load_checkpoint() -> dict:
    if not CHECKPOINT.exists():
        return {}
    try:
        d = json.loads(CHECKPOINT.read_text())
        if d.get("date") == datetime.now().strftime("%Y-%m-%d"):
            return d
        CHECKPOINT.unlink(missing_ok=True)
    except Exception as _e:
        warn(f"Checkpoint corrupto o ilegible, ignorando: {_e}")
    return {}


def _save_checkpoint(done: list, total: int):
    """Bug C fix: escritura atómica via fichero temporal + rename para evitar
    checkpoint corrupto si el proceso se interrumpe durante la escritura."""
    import tempfile as _tmp
    data = json.dumps(
        {"date": datetime.now().strftime("%Y-%m-%d"), "done": done, "total": total},
        indent=2
    )
    tmp = CHECKPOINT.with_suffix(".tmp")
    try:
        tmp.write_text(data)
        tmp.replace(CHECKPOINT)                                           
    except Exception as _e:
        warn(f"No se pudo guardar checkpoint: {_e}")
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


def source_wpscan(token: str, conn, dry_run: bool, args) -> int:
    head("WPScan API (enriquecimiento, 25 req/día plan free)")
    try:
        r = SESSION.get(
            f"{WPSCAN_BASE}/me/usage",
            headers={"Authorization": f"Token token={token}"},
            timeout=10,
        )
        if r.status_code == 200:
            d = r.json()
            info(f"Plan: {d.get('plan','?')} · Restantes hoy: {d.get('requests_remaining_today','?')}")
    except Exception as _e:
        warn(f"No se pudo consultar el uso de WPScan API: {_e}")

    cp      = _load_checkpoint()
    done    = cp.get("done", [])
    total   = 0
    slugs   = (args.plugins or TRACKED_PLUGINS) + ([] if args.plugins else TRACKED_THEMES)
    pending = [s for s in slugs if s not in done]
    info(f"{len(pending)} pendientes / {len(done)} ya procesados hoy")

    for slug in pending:
        comp_type = "theme" if slug in TRACKED_THEMES else "plugin"
        try:
            data = _wpscan_get(
                f"{'themes' if comp_type=='theme' else 'plugins'}/{slug}", token
            )
            if not data:
                done.append(slug)
                continue
            meta = data.get(slug, {})
            if meta.get("latest_version") and not dry_run:
                update_component_cache(conn, slug, comp_type, meta["latest_version"])
            vulns = _parse_wpscan_vulns(data, slug, comp_type)
            if vulns:
                ok(f"  {slug}: {len(vulns)} vulns")
                if not dry_run:
                    for v in vulns:
                        upsert_vuln(conn, v)
                    conn.commit()
            else:
                info(f"  {slug}: sin vulns nuevas")
            total += len(vulns)
            done.append(slug)
            _save_checkpoint(done, total)
            time.sleep(0.5)
        except RateLimitDailyError:
            warn(f"Cuota WPScan agotada tras {len(done)} — checkpoint guardado")
            warn("Ejecuta mañana para continuar")
            CHECKPOINT.unlink(missing_ok=True)
            return total

             
    if not args.no_core and "wp-core" not in done:
        info("WP Core vulnerabilidades...")
        seen: set = set()
        for vk in ["670", "660", "650", "643", "632", "621", "603", "581"]:
            try:
                data = _wpscan_get(f"wordpresses/{vk}", token)
            except RateLimitDailyError:
                warn("Cuota agotada consultando WP Core")
                break
            if not data:
                continue
            for entry in data.get(vk, data).get("vulnerabilities", []):
                fv = entry.get("fixed_in")
                if not fv:
                    continue
                refs = entry.get("references", {})
                cves = refs.get("cve", [])
                cve_id = f"CVE-{cves[0]}" if cves else None
                key = cve_id or entry.get("title", "")[:40]
                if key in seen:
                    continue
                seen.add(key)
                cf = entry.get("cvss") or {}
                if not isinstance(cf, dict):
                    cf = {}
                sev_raw = str(entry.get("severity") or cf.get("severity") or "medium").lower()
                sev = {"critical": "critical", "high": "high",
                       "medium": "medium", "low": "low"}.get(sev_raw, "medium")
                v = {
                    "component": "wordpress", "comp_type": "core",
                    "affects_lt": fv, "title": entry.get("title", "")[:200],
                    "severity": sev, "cvss": cf.get("score"),
                    "cve": cve_id, "fixed_in": fv,
                    "source": "wpscan",
                    "updated_at": datetime.now().isoformat(),
                }
                if not dry_run:
                    upsert_vuln(conn, v)
                total += 1
            if not dry_run:
                conn.commit()
            time.sleep(0.3)
        done.append("wp-core")
        _save_checkpoint(done, total)
        ok(f"  WP Core: {len(seen)} vulns únicas")

    CHECKPOINT.unlink(missing_ok=True)
    return total


                                                                               
                       
                                                                               


                                                                               
                                                                             
                                                                  
                                                                      
                                                                               
_NVD_SLUG_MAP: dict[str, str] = {
    "yoast seo": "wordpress-seo",
    "yoast": "wordpress-seo",
    "all in one seo": "all-in-one-seo-pack",
    "all-in-one seo": "all-in-one-seo-pack",
    "rank math": "rank-math",
    "wp forms": "wpforms-lite",
    "wpforms": "wpforms-lite",
    "ninja forms": "ninja-forms",
    "gravity forms": "gravityforms",
    "contact form 7": "contact-form-7",
    "cf7": "contact-form-7",
    "elementor pro": "elementor-pro",
    "elementor": "elementor",
    "advanced custom fields": "advanced-custom-fields",
    "acf": "advanced-custom-fields",
    "litespeed cache": "litespeed-cache",
    "w3 total cache": "w3-total-cache",
    "wp super cache": "wp-super-cache",
    "wp fastest cache": "wp-fastest-cache",
    "updraftplus": "updraftplus",
    "wordfence": "wordfence",
    "jetpack": "jetpack",
    "woocommerce payments": "woocommerce-payments",
    "woocommerce": "woocommerce",
    "bbpress": "bbpress",
    "buddypress": "buddypress",
    "ultimate member": "ultimate-member",
    "memberpress": "memberpress",
    "the events calendar": "the-events-calendar",
    "wp statistics": "wp-statistics",
    "wp mail smtp": "wp-mail-smtp",
    "loginizer": "loginizer",
    "really simple ssl": "really-simple-ssl",
    "social warfare": "social-warfare",
    "popup builder": "popup-builder",
    "nextgen gallery": "nextgen-gallery",
    "slider revolution": "revslider",
    "revolution slider": "revslider",
    "backup buddy": "backupbuddy",
    "duplicator": "duplicator",
    "akismet": "akismet",
    "polylang": "polylang",
    "wpml": "wpml",
    "givewp": "give",
    "give": "give",
    "essential addons for elementor": "essential-addons-for-elementor-lite",
    "forminator": "forminator",
    "fluent forms": "fluentform",
    "divi": "divi",
    "avada": "avada",
    "astra": "astra",
}

def _nvd_slug_from_desc(desc_lower: str, comp_type: str) -> Optional[str]:
    """
    Bug 3 fix: intenta primero el mapa de nombres conocidos antes de usar
    la extracción por regex (que genera slugs incorrectos frecuentemente).
    """
    if comp_type == "core":
        return "wordpress"

                                                                
    for name, slug in _NVD_SLUG_MAP.items():
        if name in desc_lower:
            return slug

                                                                            
    patterns = [
        r'the ([a-z0-9][a-z0-9 _-]{3,50}) plugin',
        r'([a-z0-9][a-z0-9 _-]{3,50}) plugin for wordpress',
        r'([a-z0-9][a-z0-9 _-]{3,50}) for woocommerce',
    ]
    for pat in patterns:
        import re as _re
        m = _re.search(pat, desc_lower)
        if m:
            slug = _re.sub(r'[^a-z0-9-]', '-', m.group(1).strip()).strip('-')
            slug = _re.sub(r'-{2,}', '-', slug)[:60]
            if len(slug) >= 4:                                    
                return slug
    return None

def source_nvd(conn, dry_run: bool, days_back: int = 30) -> int:
    head("NVD / NIST (gratuito, sin límite)")
    NVD   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    start = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00.000")
    end   = datetime.now().strftime("%Y-%m-%dT23:59:59.999")
    total = 0

    for keyword in ["wordpress plugin", "wordpress theme", "woocommerce", "elementor"]:
        info(f"  NVD buscando: '{keyword}'...")
        idx = 0
        while True:
            try:
                r = SESSION.get(
                    NVD,
                    params={
                        "keywordSearch":   keyword,
                        "pubStartDate":    start,
                        "pubEndDate":      end,
                        "startIndex":      idx,
                        "resultsPerPage":  100,
                    },
                    timeout=20,
                )
                if r.status_code == 403:
                    warn("NVD rate limit — esperando 30s")
                    time.sleep(30)
                    continue
                if r.status_code != 200:
                    warn(f"NVD HTTP {r.status_code}")
                    break

                data  = r.json()
                items = data.get("vulnerabilities", [])
                if not items:
                    break

                for item in items:
                    cve_data   = item.get("cve", {})
                    cve_id     = cve_data.get("id", "")
                    descs      = cve_data.get("descriptions", [])
                    desc       = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                    desc_lower = desc.lower()

                    comp_type = (
                        "core"   if ("wordpress core" in desc_lower or "wordpress before " in desc_lower)
                        else "theme"  if " theme " in desc_lower
                        else "plugin"
                    )
                                                                                   
                    slug = _nvd_slug_from_desc(desc_lower, comp_type)
                    if not slug:
                        continue

                    metrics    = cve_data.get("metrics", {})
                    cvss_score = None
                    severity   = "medium"
                    for mk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        ml = metrics.get(mk, [])
                        if ml:
                            cvss_score = ml[0].get("cvssData", {}).get("baseScore")
                            severity   = _cvss_to_severity(cvss_score)
                            break

                    fixed_in = ""
                    for cfg in cve_data.get("configurations", []):
                        for node in cfg.get("nodes", []):
                            for match in node.get("cpeMatch", []):
                                fixed_in = (
                                    match.get("versionEndExcluding", "")
                                    or match.get("versionEndIncluding", "")
                                )
                                if fixed_in:
                                    break
                            if fixed_in:
                                break
                        if fixed_in:
                            break

                                                                            
                                                                                                 
                    if not fixed_in:
                        continue

                    v = {
                        "component":   slug,
                        "comp_type":   comp_type,
                        "affects_lt":  fixed_in,
                        "title":       desc[:200],
                        "severity":    severity,
                        "cvss":        cvss_score,
                        "cve":         cve_id,
                        "fixed_in":    fixed_in,
                        "description": desc[:500],
                        "source":      "nvd",
                        "updated_at":  datetime.now().isoformat(),
                    }
                    if not dry_run:
                        upsert_vuln(conn, v)
                    total += 1

                if not dry_run:
                    conn.commit()
                idx += len(items)
                if idx >= data.get("totalResults", 0):
                    break
                time.sleep(0.6)

            except Exception as e:
                warn(f"NVD error: {e}")
                break

    ok(f"NVD: {total} vulns procesadas")
    return total


                                                                               
                       
                                                                               

def source_patchstack(conn, dry_run: bool) -> int:
    head("Patchstack (especializado WP)")
    total = 0
    endpoints = [
        "https://patchstack.com/database/wordpress/plugins?format=json&limit=200",
        "https://patchstack.com/database/api/v1/bulletins?per_page=200",
    ]
    try:
        resp = None
        for ep in endpoints:
            try:
                resp = SESSION.get(ep, timeout=15)
                if resp.status_code == 200 and resp.text.strip():
                    break
            except Exception as _e:
                warn(f"Patchstack endpoint falló: {_e}")
                continue

        if not resp or resp.status_code != 200 or not resp.text.strip():
            warn("Patchstack no disponible — saltando")
            return 0

        data  = resp.json()
        items = data if isinstance(data, list) else data.get("data", [])

        for item in items:
            slug = item.get("slug", "")
            if not slug:
                continue
            for vuln in item.get("vulnerabilities", [item]):
                fv = vuln.get("fixed_in") or vuln.get("patched_version")
                if not fv:
                    continue
                cvss = vuln.get("cvss_score") or vuln.get("score")
                sev  = _cvss_to_severity(cvss) if cvss else vuln.get("severity", "medium")
                v = {
                    "component":   slug,
                    "comp_type":   item.get("type", "plugin"),
                    "affects_lt":  fv,
                    "title":       vuln.get("title", "")[:200],
                    "severity":    sev,
                    "cvss":        cvss,
                    "cve":         vuln.get("cve_id") or vuln.get("cve"),
                    "fixed_in":    fv,
                    "source":      "patchstack",
                    "updated_at":  datetime.now().isoformat(),
                }
                if not dry_run:
                    upsert_vuln(conn, v)
                total += 1

        if not dry_run:
            conn.commit()
        ok(f"Patchstack: {total} vulns")

    except Exception as e:
        warn(f"Patchstack error: {e}")

    return total


                                                                               
                               
                                                                               

def source_github(conn, dry_run: bool, gh_token: str = "") -> int:
    head("GitHub Advisory Database (GHSA)")
    Q = """query($cursor:String){
  securityAdvisories(ecosystem:WORDPRESS,first:100,after:$cursor){
    pageInfo{hasNextPage endCursor}
    nodes{
      ghsaId summary severity cvss{score}
      identifiers{type value}
      vulnerabilities(first:5){nodes{
        package{name}
        firstPatchedVersion{identifier}
        vulnerableVersionRange
      }}
    }
  }
}"""
    SEV = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "LOW": "low"}
    hdrs = {"Content-Type": "application/json", "User-Agent": "WPVulnScanner/3.0"}
    if gh_token:
        hdrs["Authorization"] = f"Bearer {gh_token}"

    total  = 0
    cursor = None

    for page in range(10):
        try:
            r = SESSION.post(
                "https://api.github.com/graphql",
                json={"query": Q, "variables": {"cursor": cursor}},
                headers=hdrs,
                timeout=15,
            )
            if r.status_code in (401, 403):
                warn(f"GitHub HTTP {r.status_code} — sin token o rate limit")
                break
            if r.status_code != 200:
                warn(f"GitHub HTTP {r.status_code}")
                break

            sa = r.json().get("data", {}).get("securityAdvisories", {})
            for node in sa.get("nodes", []):
                sev    = SEV.get(node.get("severity", ""), "medium")
                cvss   = node.get("cvss", {}).get("score")
                cve_id = next(
                    (i["value"] for i in node.get("identifiers", []) if i["type"] == "CVE"),
                    None,
                )
                for vuln in node.get("vulnerabilities", {}).get("nodes", []):
                    slug = (vuln.get("package", {}).get("name") or "").lower().replace(" ", "-")
                    fv   = (vuln.get("firstPatchedVersion") or {}).get("identifier")
                    if not slug or not fv:
                        continue
                                                                               
                                                                       
                    _gh_type = "core" if slug in ("wordpress", "wordpress-core") else "plugin"
                    v = {
                        "component":   slug,
                        "comp_type":   _gh_type,
                        "affects_lt":  fv,
                        "title":       node.get("summary", "")[:200],
                        "severity":    sev,
                        "cvss":        cvss,
                        "cve":         cve_id,
                        "fixed_in":    fv,
                        "source":      "github-advisory",
                        "updated_at":  datetime.now().isoformat(),
                    }
                    if not dry_run:
                        upsert_vuln(conn, v)
                    total += 1

            if not dry_run:
                conn.commit()

            pi = sa.get("pageInfo", {})
            if not pi.get("hasNextPage"):
                break
            cursor = pi.get("endCursor")
            time.sleep(0.5)

        except Exception as e:
            warn(f"GitHub error: {e}")
            break

    ok(f"GitHub Advisory: {total} vulns")
    return total


                                                                               
                         
                                                                               

def source_offline(conn, dry_run: bool) -> int:
    head("Base offline (seed garantizado)")
    if not dry_run:
        _seed_offline(conn)
    ok(f"Offline seed: {len(OFFLINE_SEED)} vulns")
    return len(OFFLINE_SEED)


                                                                               
      
                                                                               

def main():
    parser = argparse.ArgumentParser(
        description="WP VulnScanner — Actualizador multi-fuente v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python update_vulns.py                        # actualización completa
  python update_vulns.py --source wordfence     # solo Wordfence Intelligence
  python update_vulns.py --source wordfence --full  # descarga completa (sin delta)
  python update_vulns.py --source nvd --days 7  # NVD últimos 7 días
  python update_vulns.py --stats                # ver estadísticas BD
  python update_vulns.py --dry-run              # simular sin escribir
        """,
    )
    parser.add_argument(
        "--source",
        choices=["all", "wordfence", "wpscan", "nvd", "patchstack", "github", "offline"],
        default="all",
        help="Fuente a actualizar (default: all)",
    )
    parser.add_argument("--token",     help="WPScan API token (o WPSCAN_API_TOKEN en .env)")
    parser.add_argument("--gh-token",  help="GitHub Personal Access Token (mejora rate limit)")
    parser.add_argument("--dry-run",   action="store_true", help="Simular sin escribir en BD")
    parser.add_argument("--stats",     action="store_true", help="Mostrar estadísticas BD y salir")
    parser.add_argument("--days",      type=int, default=30, help="Días hacia atrás para NVD (default: 30)")
    parser.add_argument("--plugins",   nargs="+", help="Plugins específicos para WPScan")
    parser.add_argument("--no-core",   action="store_true", help="Saltar WP Core en WPScan")
    parser.add_argument(
        "--full",
        action="store_true",
        help="Descarga completa de Wordfence (ignora delta/cache)",
    )
    args = parser.parse_args()

                 
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    print(f"\n{C.W}{'─'*60}")
    print("  WP VulnScanner — Actualizador multi-fuente v3.0")
    print(f"{'─'*60}{C.Z}")
    print(f"  BD:    {VULNS_DB_PATH}")
    print(f"  Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    print(f"  Modo:  {'DRY RUN (sin escritura)' if args.dry_run else 'ESCRITURA'}")
    print(f"  Wordfence: {'descarga completa' if args.full else 'incremental (delta 48h)'}")

    init_vulns_db()

    if args.stats:
        stats = get_db_stats()
        print(f"\n{C.W}Estadísticas vulns.db:{C.Z}")
        print(f"  Total CVEs:    {stats['total_vulns']:,}")
        print(f"  Componentes:   {stats['components']:,}")
        print(f"  Críticas:      {stats.get('critical', '?')}")
        print(f"  Última update: {stats['last_update']}")
        print("\n  Por fuente:")
        for s in stats.get("by_source", []):
            print(f"    {s['source']:<28} {s['cnt']:>6,} vulns")
        return

    conn = get_conn()
    wpscan_token = args.token or os.environ.get("WPSCAN_API_TOKEN", "")
    gh_token     = getattr(args, "gh_token", None) or os.environ.get("GITHUB_TOKEN", "")
    use_all      = args.source == "all"
    total        = 0

    if use_all or args.source == "offline":
        total += source_offline(conn, args.dry_run)

    if use_all or args.source == "wordfence":
        total += source_wordfence_intelligence(
            conn, args.dry_run,
            incremental=not args.full,
        )

    if use_all or args.source == "patchstack":
        total += source_patchstack(conn, args.dry_run)

    if use_all or args.source == "nvd":
        total += source_nvd(conn, args.dry_run, args.days)

    if use_all or args.source == "github":
        total += source_github(conn, args.dry_run, gh_token)

    if use_all or args.source == "wpscan":
        if wpscan_token:
            total += source_wpscan(wpscan_token, conn, args.dry_run, args)
        elif args.source == "wpscan":
            err("Requiere WPSCAN_API_TOKEN en .env o --token")
            sys.exit(1)
        else:
            warn("WPSCAN_API_TOKEN no configurado — saltando fuente WPScan (opcional)")

                                        
    if not args.dry_run and total > 0:
        set_meta(conn, "last_update", datetime.now().isoformat())
        set_meta(conn, "last_source",  args.source)
        conn.commit()

    conn.close()

                   
    stats = get_db_stats()
    print(f"\n{C.W}{'─'*40}")
    print(f"  Resultado{C.Z}")
    print(f"  CVEs en BD:   {stats['total_vulns']:,}")
    print(f"  Componentes:  {stats['components']:,}")
    print("  Por fuente:")
    for s in stats.get("by_source", []):
        print(f"    {s['source']:<28} {s['cnt']:>6,} vulns")

    if args.dry_run:
        warn("DRY RUN — nada fue escrito en BD")
    else:
        ok(f"BD actualizada: {VULNS_DB_PATH}")
        print(f"\n{C.G}Reinicia app.py para aplicar los cambios{C.Z}\n")


if __name__ == "__main__":
    main()

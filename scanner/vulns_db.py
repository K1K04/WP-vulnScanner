"""
WP VulnScanner — Base de datos de vulnerabilidades
=======================================================
BD SQLite separada (vulns.db) con soporte multi-fuente:
  - WPScan API (con token, enriquecimiento)
  - NVD / NIST (gratuito, sin límite diario)
  - Patchstack (gratuito, especializado en WP)
  - GitHub Advisory Database (GraphQL, gratuito)
  - Base offline hardcodeada (siempre disponible)

El scanner NUNCA llama APIs externas durante un escaneo.
Solo consulta esta BD local. La BD se actualiza con update_vulns.py.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

log = logging.getLogger("wpvulnscan.vulnsdb")

                                                                                
                                                                    
from scanner.utils import _version_lt

_DEFAULT_VULNS_DB_PATH = Path(__file__).parent.parent / "vulns.db"
_VULNS_DB_PATH_ENV = os.environ.get("VULNS_DB_PATH", "").strip()
if _VULNS_DB_PATH_ENV:
    _vulns_candidate = Path(_VULNS_DB_PATH_ENV).expanduser()
    if not _vulns_candidate.is_absolute():
        _vulns_candidate = (Path(__file__).parent.parent / _vulns_candidate).resolve()
    VULNS_DB_PATH = _vulns_candidate
else:
    VULNS_DB_PATH = _DEFAULT_VULNS_DB_PATH

VULNS_DB_PATH.parent.mkdir(parents=True, exist_ok=True)


                                                                               
        
                                                                               

SCHEMA = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    component   TEXT    NOT NULL,  -- plugin slug, theme slug, o 'wordpress'
    comp_type   TEXT    NOT NULL DEFAULT 'plugin',  -- 'plugin','theme','core'
    affects_lt  TEXT    NOT NULL,  -- versión que corrige (< esta = vulnerable)
    affects_gte TEXT,              -- versión mínima afectada (opcional)
    title       TEXT    NOT NULL,
    severity    TEXT    NOT NULL DEFAULT 'medium',
    cvss        REAL,
    cvss_vector TEXT,              -- CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cve         TEXT,
    url         TEXT,
    fixed_in    TEXT,
    description TEXT,
    epss        REAL,              -- EPSS probability 0.0-1.0
    kev         INTEGER DEFAULT 0, -- 1 = en CISA KEV catalog
    source      TEXT    NOT NULL DEFAULT 'offline',
    updated_at  TEXT    NOT NULL,
    UNIQUE(component, cve, affects_lt) ON CONFLICT REPLACE
);

CREATE INDEX IF NOT EXISTS idx_component ON vulnerabilities(component);
CREATE INDEX IF NOT EXISTS idx_cve       ON vulnerabilities(cve);
CREATE INDEX IF NOT EXISTS idx_severity  ON vulnerabilities(severity);

CREATE TABLE IF NOT EXISTS db_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS component_cache (
    slug        TEXT PRIMARY KEY,
    comp_type   TEXT NOT NULL DEFAULT 'plugin',
    latest_version TEXT,
    cached_at   TEXT NOT NULL
);
"""


                                                                               
          
                                                                               

def get_conn(db_path: Path = VULNS_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_vulns_db(db_path: Path = VULNS_DB_PATH):
    """Inicializa el schema y carga datos offline si la BD está vacía."""
    conn = get_conn(db_path)
    conn.executescript(SCHEMA)
                                                                             
    for col, typedef in [
        ("cvss_vector", "TEXT"),
        ("epss",        "REAL"),
        ("kev",         "INTEGER DEFAULT 0"),
    ]:
        try:
            conn.execute(f"ALTER TABLE vulnerabilities ADD COLUMN {col} {typedef}")
        except Exception as _e:
            try:
                log = globals().get("log")
                if log:
                    log.debug("vulns_db alter column suppressed: %s (%s)", _e, col)
            except Exception:
                pass             
    conn.commit()

                                         
    count = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
    if count == 0:
        log.info("BD de vulnerabilidades vacía — cargando datos offline...")
        _seed_offline(conn)
        log.info("BD inicializada con datos offline")
    conn.close()


                                                                               
           
                                                                               

def get_vulns_for_component(slug: str, version: Optional[str] = None,
                             confidence: int = 100,
                             db_path: Path = VULNS_DB_PATH) -> list[dict]:
    """
    Devuelve vulnerabilidades para un plugin/tema/core.
    Si se pasa version, filtra solo las que afectan a esa versión.

    FIX-2: Cuando version=None (no detectada), devuelve SOLO las vulns que
    no tienen versión de fix conocida (fixed_in IS NULL / affects_lt vacío).
    Antes devolvía todas las vulns del slug, generando falsos positivos masivos
    cuando un plugin se detectaba por presencia pero sin versión conocida.
    """
    conn = get_conn(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM vulnerabilities WHERE component=? ORDER BY cvss DESC NULLS LAST, severity",
            (slug,)
        ).fetchall()

        if not rows:
            return []

        result = []
        for row in rows:
            r = dict(row)
            affects_lt = r.get("affects_lt") or ""

            if version:
                                                              
                if affects_lt and not _version_lt(version, affects_lt):
                    continue                                    
                                                                       
                affects_gte = r.get("affects_gte") or ""
                if affects_gte and version and _version_lt(version, affects_gte):
                    continue                                      
            else:
                                                                                    
                                                                               
                                                                                   
                                                                              
                if affects_lt and affects_lt != "0":
                    if (confidence or 0) < 85:
                        continue                                                        
                r["version_unconfirmed"] = True

            result.append(r)

        return result
    finally:
        conn.close()


def get_latest_version(slug: str, db_path: Path = VULNS_DB_PATH) -> Optional[str]:
    """Versión más reciente conocida del componente (desde cache)."""
    conn = get_conn(db_path)
    try:
        row = conn.execute(
            "SELECT latest_version, cached_at FROM component_cache WHERE slug=?", (slug,)
        ).fetchone()
        if not row:
            return None
                             
        try:
            cached = datetime.fromisoformat(row["cached_at"])
            if datetime.now() - cached > timedelta(days=7):
                return None
        except Exception as _e:
            log.debug("non-critical path suppressed: %s", _e)
        return row["latest_version"]
    finally:
        conn.close()


def get_known_plugin_slugs(db_path: Path = VULNS_DB_PATH) -> list[str]:
    """
    FIX-1: Devuelve todos los slugs de plugins/temas conocidos en la BD de
    vulnerabilidades + component_cache. Permite que el dict-probe del scanner
    use esta lista dinámica en lugar de un array hardcodeado en el código.
    Incluye deduplicación y ordena por número de CVEs (más relevantes primero).
    """
    conn = get_conn(db_path)
    try:
                                                                         
        rows_v = conn.execute(
            """SELECT component, COUNT(*) as cnt
               FROM vulnerabilities
               WHERE comp_type IN ('plugin','theme')
               GROUP BY component
               ORDER BY cnt DESC"""
        ).fetchall()
        slugs_v = [r[0] for r in rows_v if r[0] and r[0] != "wordpress"]

                                                                       
        rows_c = conn.execute(
            "SELECT slug FROM component_cache WHERE comp_type IN ('plugin','theme')"
        ).fetchall()
        slugs_c = [r[0] for r in rows_c if r[0]]

                                                     
        seen: set[str] = set()
        result: list[str] = []
        for s in slugs_v + slugs_c:
            if s not in seen:
                seen.add(s)
                result.append(s)
        return result
    except Exception as e:
        log.warning("get_known_plugin_slugs: %s", e)
        return []
    finally:
        conn.close()


def get_db_stats(db_path: Path = VULNS_DB_PATH) -> dict:
    """Estadísticas de la BD para mostrar en el dashboard."""
    conn = get_conn(db_path)
    try:
        total     = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        by_source = conn.execute(
            "SELECT source, COUNT(*) as cnt FROM vulnerabilities GROUP BY source"
        ).fetchall()
        by_sev    = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM vulnerabilities GROUP BY severity"
        ).fetchall()
        components = conn.execute(
            "SELECT COUNT(DISTINCT component) FROM vulnerabilities"
        ).fetchone()[0]
        last_update = conn.execute(
            "SELECT value FROM db_meta WHERE key='last_update'"
        ).fetchone()
        critical = conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE severity='critical'"
        ).fetchone()[0]

        return {
            "total_vulns":  total,
            "components":   components,
            "critical":     critical,
            "by_source":    [dict(r) for r in by_source],
            "by_severity":  [dict(r) for r in by_sev],
            "last_update":  last_update["value"] if last_update else "Nunca",
            "db_path":      str(db_path),
        }
    finally:
        conn.close()


def get_db_freshness(db_path: Path = VULNS_DB_PATH) -> dict:
    """Devuelve si la BD está al día y cuántos días lleva sin actualizar."""
    conn = get_conn(db_path)
    try:
        row = conn.execute(
            "SELECT value FROM db_meta WHERE key='last_update'"
        ).fetchone()
        if not row:
            return {"fresh": False, "days_old": 999, "last_update": None}
        try:
            last = datetime.fromisoformat(row["value"])
            days_old = (datetime.now() - last).days
            return {
                "fresh":       days_old <= 7,
                "days_old":    days_old,
                "last_update": row["value"],
            }
        except Exception:
            return {"fresh": False, "days_old": 999, "last_update": row["value"]}
    finally:
        conn.close()


                                                                               
           
                                                                               

def upsert_vuln(conn: sqlite3.Connection, v: dict):
    """Inserta o actualiza una vulnerabilidad (incluye cvss_vector, epss, kev)."""
    conn.execute("""
        INSERT INTO vulnerabilities
            (component, comp_type, affects_lt, affects_gte, title, severity,
             cvss, cvss_vector, cve, url, fixed_in, description,
             epss, kev, source, updated_at)
        VALUES
            (:component,:comp_type,:affects_lt,:affects_gte,:title,:severity,
             :cvss,:cvss_vector,:cve,:url,:fixed_in,:description,
             :epss,:kev,:source,:updated_at)
        ON CONFLICT(component, cve, affects_lt) DO UPDATE SET
            title=excluded.title, severity=excluded.severity,
            cvss=excluded.cvss, cvss_vector=COALESCE(excluded.cvss_vector, cvss_vector),
            description=COALESCE(NULLIF(excluded.description,''), description),
            epss=COALESCE(excluded.epss, epss),
            kev=MAX(excluded.kev, kev),
            source=excluded.source, updated_at=excluded.updated_at
    """, {
        "component":   v.get("component") or v.get("slug", ""),
        "comp_type":   v.get("comp_type", "plugin"),
        "affects_lt":  v.get("affects_lt") or v.get("fixed_in", ""),
        "affects_gte": v.get("affects_gte"),
        "title":       v.get("title", ""),
        "severity":    v.get("severity", "medium"),
        "cvss":        v.get("cvss"),
        "cvss_vector": v.get("cvss_vector"),
        "cve":         v.get("cve"),
        "url":         v.get("url"),
        "fixed_in":    v.get("fixed_in") or v.get("affects_lt", ""),
        "description": v.get("description"),
        "epss":        v.get("epss"),
        "kev":         int(bool(v.get("kev", 0))),
        "source":      v.get("source", "offline"),
        "updated_at":  v.get("updated_at") or datetime.now().isoformat(),
    })


def update_component_cache(conn: sqlite3.Connection, slug: str,
                            comp_type: str, latest_version: str):
    conn.execute("""
        INSERT INTO component_cache (slug, comp_type, latest_version, cached_at)
        VALUES (?,?,?,?)
        ON CONFLICT(slug) DO UPDATE SET
            latest_version=excluded.latest_version, cached_at=excluded.cached_at
    """, (slug, comp_type, latest_version, datetime.now().isoformat()))


def set_meta(conn: sqlite3.Connection, key: str, value: str):
    conn.execute(
        "INSERT INTO db_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value)
    )


                                                                               
                                                                  
                                                                               


                                                                               
                                                                
                                                                               

OFFLINE_SEED = [
                                                                                
    {"component":"wordpress","comp_type":"core","affects_lt":"6.7.2","title":"WordPress < 6.7.2 — Path Traversal en temas de bloques","severity":"high","cvss":7.5,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","cve":"CVE-2025-22867","url":"https://nvd.nist.gov/vuln/detail/CVE-2025-22867","fixed_in":"6.7.2","source":"offline"},
    {"component":"wordpress","comp_type":"core","affects_lt":"6.6.2","title":"WordPress < 6.6.2 — XSS almacenado en el editor de bloques","severity":"high","cvss":7.2,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N","cve":"CVE-2024-6207","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-6207","fixed_in":"6.6.2","source":"offline"},
    {"component":"wordpress","comp_type":"core","affects_lt":"6.4.2","title":"WordPress < 6.4.2 — RCE vía POP chain en deserialización","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2023-56764","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-56764","fixed_in":"6.4.2","kev":1,"source":"offline"},
    {"component":"wordpress","comp_type":"core","affects_lt":"6.3.2","title":"WordPress < 6.3.2 — XSS almacenado en comentarios","severity":"high","cvss":7.5,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","cve":"CVE-2023-5561","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-5561","fixed_in":"6.3.2","source":"offline"},
    {"component":"wordpress","comp_type":"core","affects_lt":"6.2.1","title":"WordPress < 6.2.1 — Directory Traversal en importación de temas","severity":"high","cvss":7.5,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","cve":"CVE-2023-2745","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-2745","fixed_in":"6.2.1","source":"offline"},
    {"component":"wordpress","comp_type":"core","affects_lt":"6.0.3","title":"WordPress < 6.0.3 — XSS en parámetro de búsqueda","severity":"medium","cvss":6.1,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","cve":"CVE-2022-43497","url":"https://nvd.nist.gov/vuln/detail/CVE-2022-43497","fixed_in":"6.0.3","source":"offline"},
    {"component":"wordpress","comp_type":"core","affects_lt":"5.9.4","title":"WordPress < 5.9.4 — SQLi en WP_Query (sin preparar)","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2022-21661","url":"https://nvd.nist.gov/vuln/detail/CVE-2022-21661","fixed_in":"5.9.4","kev":1,"source":"offline"},
                                                                               
    {"component":"contact-form-7","comp_type":"plugin","affects_lt":"5.3.2","title":"Contact Form 7 < 5.3.2 — Subida de archivos sin restricción (RCE)","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2020-35489","url":"https://nvd.nist.gov/vuln/detail/CVE-2020-35489","fixed_in":"5.3.2","kev":1,"source":"offline"},
    {"component":"contact-form-7","comp_type":"plugin","affects_lt":"5.9.0","title":"Contact Form 7 < 5.9.0 — CSRF en módulo de carga de archivos","severity":"high","cvss":7.5,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N","cve":"CVE-2023-6449","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-6449","fixed_in":"5.9.0","source":"offline"},
                                                                               
    {"component":"woocommerce","comp_type":"plugin","affects_lt":"5.5.1","title":"WooCommerce < 5.5.1 — SQL Injection sin autenticación","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2021-32789","url":"https://nvd.nist.gov/vuln/detail/CVE-2021-32789","fixed_in":"5.5.1","kev":1,"source":"offline"},
    {"component":"woocommerce","comp_type":"plugin","affects_lt":"7.8.0","title":"WooCommerce < 7.8.0 — Broken Access Control en pedidos","severity":"high","cvss":7.5,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","cve":"CVE-2023-28121","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-28121","fixed_in":"7.8.0","source":"offline"},
                                                                               
                                                                                          
    {"component":"woocommerce-payments","comp_type":"plugin","affects_lt":"5.6.2","title":"WooCommerce Payments < 5.6.2 — Bypass de autenticación (admin takeover)","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2023-28121","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-28121","fixed_in":"5.6.2","kev":1,"source":"offline"},
                                                                               
    {"component":"elementor","comp_type":"plugin","affects_lt":"3.13.2","title":"Elementor < 3.13.2 — RCE por subida de SVG malicioso","severity":"critical","cvss":9.9,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H","cve":"CVE-2023-2106","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-2106","fixed_in":"3.13.2","source":"offline"},
    {"component":"elementor","comp_type":"plugin","affects_lt":"3.16.5","title":"Elementor < 3.16.5 — CSRF + XSS en editor de widgets","severity":"high","cvss":7.1,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","cve":"CVE-2023-41955","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-41955","fixed_in":"3.16.5","source":"offline"},
    {"component":"elementor","comp_type":"plugin","affects_lt":"3.18.0","title":"Elementor < 3.18.0 — XSS almacenado via widget HTML","severity":"high","cvss":7.2,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N","cve":"CVE-2024-2091","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-2091","fixed_in":"3.18.0","source":"offline"},
                                                                               
                                                                           
    {"component":"elementor-pro","comp_type":"plugin","affects_lt":"3.11.7","title":"Elementor Pro < 3.11.7 — Toma de control de sitio sin autenticación","severity":"critical","cvss":9.9,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cve":"CVE-2023-32243","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-32243","fixed_in":"3.11.7","kev":1,"source":"offline"},
                                                                               
    {"component":"wordpress-seo","comp_type":"plugin","affects_lt":"21.9.0","title":"Yoast SEO < 21.9 — XSS reflejado en metabox","severity":"medium","cvss":5.4,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N","cve":"CVE-2024-1386","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-1386","fixed_in":"21.9.0","source":"offline"},
                                                                               
    {"component":"all-in-one-seo-pack","comp_type":"plugin","affects_lt":"4.3.1","title":"All in One SEO < 4.3.1 — SQLi autenticado en búsqueda","severity":"high","cvss":7.7,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N","cve":"CVE-2023-0585","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-0585","fixed_in":"4.3.1","source":"offline"},
    {"component":"all-in-one-seo-pack","comp_type":"plugin","affects_lt":"4.5.4","title":"All in One SEO < 4.5.4 — XSS almacenado via shortcode","severity":"high","cvss":7.2,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N","cve":"CVE-2023-6316","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-6316","fixed_in":"4.5.4","source":"offline"},
                                                                               
    {"component":"rank-math","comp_type":"plugin","affects_lt":"1.0.214","title":"Rank Math SEO < 1.0.214 — Escalada de privilegios sin autenticación","severity":"critical","cvss":10.0,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cve":"CVE-2020-11514","url":"https://nvd.nist.gov/vuln/detail/CVE-2020-11514","fixed_in":"1.0.214","kev":1,"source":"offline"},
                                                                               
    {"component":"really-simple-ssl","comp_type":"plugin","affects_lt":"9.1.1","title":"Really Simple SSL < 9.1.1 — Bypass de autenticación 2FA (admin takeover)","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2024-10924","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-10924","fixed_in":"9.1.1","kev":1,"source":"offline"},
                                                                               
    {"component":"wordfence","comp_type":"plugin","affects_lt":"7.10.3","title":"Wordfence < 7.10.3 — XSS almacenado en configuración de WAF","severity":"medium","cvss":5.4,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N","cve":"CVE-2023-2732","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-2732","fixed_in":"7.10.3","source":"offline"},
                                                                               
    {"component":"loginizer","comp_type":"plugin","affects_lt":"1.6.4","title":"Loginizer < 1.6.4 — SQL Injection en formulario de login","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2020-27615","url":"https://nvd.nist.gov/vuln/detail/CVE-2020-27615","fixed_in":"1.6.4","kev":1,"source":"offline"},
                                                                               
    {"component":"wpforms-lite","comp_type":"plugin","affects_lt":"1.8.7","title":"WPForms < 1.8.7 — XSS almacenado sin autenticación","severity":"high","cvss":7.2,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","cve":"CVE-2024-1786","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-1786","fixed_in":"1.8.7","source":"offline"},
    {"component":"wpforms-lite","comp_type":"plugin","affects_lt":"1.8.4","title":"WPForms < 1.8.4 — IDOR en envíos de formulario","severity":"medium","cvss":5.4,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N","cve":"CVE-2023-4274","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-4274","fixed_in":"1.8.4","source":"offline"},
                                                                               
    {"component":"ninja-forms","comp_type":"plugin","affects_lt":"3.6.26","title":"Ninja Forms < 3.6.26 — XSS almacenado vía campo de email","severity":"high","cvss":7.6,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","cve":"CVE-2023-37979","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-37979","fixed_in":"3.6.26","source":"offline"},
    {"component":"ninja-forms","comp_type":"plugin","affects_lt":"3.6.10","title":"Ninja Forms < 3.6.10 — RCE por deserialización PHP","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2022-1781","url":"https://nvd.nist.gov/vuln/detail/CVE-2022-1781","fixed_in":"3.6.10","kev":1,"source":"offline"},
                                                                               
    {"component":"litespeed-cache","comp_type":"plugin","affects_lt":"5.7","title":"LiteSpeed Cache < 5.7 — Escalada de privilegios sin autenticación","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2023-40000","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-40000","fixed_in":"5.7","kev":1,"source":"offline"},
    {"component":"litespeed-cache","comp_type":"plugin","affects_lt":"6.3.0.1","title":"LiteSpeed Cache < 6.3.0.1 — XSS almacenado sin autenticación","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2024-28000","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-28000","fixed_in":"6.3.0.1","kev":1,"source":"offline"},
                                                                               
    {"component":"w3-total-cache","comp_type":"plugin","affects_lt":"2.4.0","title":"W3 Total Cache < 2.4.0 — SSRF sin autenticación (expose cloud keys)","severity":"high","cvss":8.6,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N","cve":"CVE-2024-12365","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-12365","fixed_in":"2.4.0","source":"offline"},
                                                                               
    {"component":"wp-super-cache","comp_type":"plugin","affects_lt":"1.7.9","title":"WP Super Cache < 1.7.9 — RCE en panel de configuración","severity":"critical","cvss":10.0,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cve":"CVE-2023-2641","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-2641","fixed_in":"1.7.9","source":"offline"},
                                                                               
    {"component":"updraftplus","comp_type":"plugin","affects_lt":"1.23.10","title":"UpdraftPlus < 1.23.10 — Descarga de backups sin autenticación","severity":"critical","cvss":9.6,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N","cve":"CVE-2023-32960","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-32960","fixed_in":"1.23.10","source":"offline"},
    {"component":"updraftplus","comp_type":"plugin","affects_lt":"1.22.22","title":"UpdraftPlus < 1.22.22 — Acceso a backups por usuario de bajo privilegio","severity":"high","cvss":8.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N","cve":"CVE-2022-0633","url":"https://nvd.nist.gov/vuln/detail/CVE-2022-0633","fixed_in":"1.22.22","source":"offline"},
                                                                               
    {"component":"gravityforms","comp_type":"plugin","affects_lt":"2.7.4","title":"Gravity Forms < 2.7.4 — PHP Object Injection en importación","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2023-28782","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-28782","fixed_in":"2.7.4","source":"offline"},
                                                                               
    {"component":"jetpack","comp_type":"plugin","affects_lt":"13.2.0","title":"Jetpack < 13.2 — Inyección de código en shortcodes","severity":"high","cvss":8.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N","cve":"CVE-2024-2010","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-2010","fixed_in":"13.2.0","source":"offline"},
    {"component":"jetpack","comp_type":"plugin","affects_lt":"12.1.1","title":"Jetpack < 12.1.1 — Exposición de correos electrónicos de usuarios","severity":"medium","cvss":5.3,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","cve":"CVE-2023-2996","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-2996","fixed_in":"12.1.1","source":"offline"},
                                                                               
    {"component":"nextgen-gallery","comp_type":"plugin","affects_lt":"3.37","title":"NextGEN Gallery < 3.37 — SQL Injection autenticada","severity":"high","cvss":7.7,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N","cve":"CVE-2023-3154","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-3154","fixed_in":"3.37","source":"offline"},
                                                                               
    {"component":"revslider","comp_type":"plugin","affects_lt":"4.1.5","title":"Slider Revolution < 4.1.5 — LFI sin autenticación (lectura de archivos)","severity":"critical","cvss":9.3,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","cve":"CVE-2014-9734","url":"https://nvd.nist.gov/vuln/detail/CVE-2014-9734","fixed_in":"4.1.5","kev":1,"source":"offline"},
    {"component":"revslider","comp_type":"plugin","affects_lt":"6.6.12","title":"Slider Revolution < 6.6.12 — LFI en carga de imágenes","severity":"high","cvss":7.5,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","cve":"CVE-2023-1874","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-1874","fixed_in":"6.6.12","source":"offline"},
                                                                               
    {"component":"advanced-custom-fields","comp_type":"plugin","affects_lt":"6.2.5","title":"ACF < 6.2.5 — XSS reflejado sin autenticación","severity":"high","cvss":7.2,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","cve":"CVE-2023-40680","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-40680","fixed_in":"6.2.5","source":"offline"},
                                                                              
    {"component":"advanced-custom-fields-pro","comp_type":"plugin","affects_lt":"6.2.5","title":"ACF Pro < 6.2.5 — XSS reflejado sin autenticación","severity":"high","cvss":7.2,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","cve":"CVE-2023-40681","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-40681","fixed_in":"6.2.5","source":"offline"},
                                                                               
    {"component":"bbpress","comp_type":"plugin","affects_lt":"2.6.7","title":"bbPress < 2.6.7 — Escalada de privilegios en roles de usuario","severity":"high","cvss":8.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N","cve":"CVE-2020-8772","url":"https://nvd.nist.gov/vuln/detail/CVE-2020-8772","fixed_in":"2.6.7","source":"offline"},
                                                                               
    {"component":"buddypress","comp_type":"plugin","affects_lt":"9.1.1","title":"BuddyPress < 9.1.1 — REST API privilege escalation","severity":"high","cvss":8.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N","cve":"CVE-2021-21389","url":"https://nvd.nist.gov/vuln/detail/CVE-2021-21389","fixed_in":"9.1.1","source":"offline"},
                                                                               
    {"component":"wp-mail-smtp","comp_type":"plugin","affects_lt":"3.8.0","title":"WP Mail SMTP < 3.8.0 — Exposición de credenciales SMTP","severity":"high","cvss":7.5,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","cve":"CVE-2023-2253","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-2253","fixed_in":"3.8.0","source":"offline"},
                                                                               
    {"component":"social-warfare","comp_type":"plugin","affects_lt":"3.5.3","title":"Social Warfare < 3.5.3 — RCE sin autenticación vía SWP_URL","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2019-9978","url":"https://nvd.nist.gov/vuln/detail/CVE-2019-9978","fixed_in":"3.5.3","kev":1,"source":"offline"},
                                                                               
    {"component":"popup-builder","comp_type":"plugin","affects_lt":"4.2.3","title":"Popup Builder < 4.2.3 — Inyección de código sin autenticación","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2023-6000","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-6000","fixed_in":"4.2.3","kev":1,"source":"offline"},
                                                                               
    {"component":"ultimate-member","comp_type":"plugin","affects_lt":"2.6.7","title":"Ultimate Member < 2.6.7 — Escalada de privilegios sin autenticación","severity":"critical","cvss":10.0,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cve":"CVE-2023-3460","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-3460","fixed_in":"2.6.7","kev":1,"source":"offline"},
                                                                               
    {"component":"wpml","comp_type":"plugin","affects_lt":"4.6.9","title":"WPML < 4.6.9 — SSRF en importación de traducciones","severity":"high","cvss":7.7,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N","cve":"CVE-2024-6386","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-6386","fixed_in":"4.6.9","source":"offline"},
                                                                               
    {"component":"give","comp_type":"plugin","affects_lt":"3.14.2","title":"GiveWP < 3.14.2 — PHP Object Injection sin autenticación (RCE)","severity":"critical","cvss":10.0,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cve":"CVE-2024-5932","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-5932","fixed_in":"3.14.2","kev":1,"source":"offline"},
                                                                               
    {"component":"wp-statistics","comp_type":"plugin","affects_lt":"14.5","title":"WP Statistics < 14.5 — SQL Injection sin autenticación","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2024-2194","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-2194","fixed_in":"14.5","source":"offline"},
                                                                               
    {"component":"wp-fastest-cache","comp_type":"plugin","affects_lt":"1.2.2","title":"WP Fastest Cache < 1.2.2 — SQL Injection sin autenticación","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2023-6063","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-6063","fixed_in":"1.2.2","source":"offline"},
                                                                               
                                                                               
    {"component":"essential-addons-for-elementor-lite","comp_type":"plugin","affects_lt":"5.7.2","title":"Essential Addons for Elementor < 5.7.2 — Privilege Escalation sin auth","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2023-24747","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-24747","fixed_in":"5.7.2","source":"offline"},
                                                                               
    {"component":"backupbuddy","comp_type":"plugin","affects_lt":"8.7.5.1","title":"BackupBuddy < 8.7.5.1 — LFI / Descarga de archivos arbitrarios","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","cve":"CVE-2022-31474","url":"https://nvd.nist.gov/vuln/detail/CVE-2022-31474","fixed_in":"8.7.5.1","kev":1,"source":"offline"},
                                                                               
    {"component":"profilepress","comp_type":"plugin","affects_lt":"3.1.4","title":"ProfilePress < 3.1.4 — Escalada de privilegios en registro","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2021-34643","url":"https://nvd.nist.gov/vuln/detail/CVE-2021-34643","fixed_in":"3.1.4","source":"offline"},
                                                                               
    {"component":"akismet","comp_type":"plugin","affects_lt":"5.3.0","title":"Akismet < 5.3 — SSRF en verificación de comentarios","severity":"medium","cvss":5.3,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","cve":"CVE-2023-6808","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-6808","fixed_in":"5.3.0","source":"offline"},
                                                                               
    {"component":"the-events-calendar","comp_type":"plugin","affects_lt":"6.2.8","title":"The Events Calendar < 6.2.8 — SQL Injection sin autenticación","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2024-2961","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-2961","fixed_in":"6.2.8","source":"offline"},
                                                                               
    {"component":"memberpress","comp_type":"plugin","affects_lt":"1.11.26","title":"MemberPress < 1.11.26 — SQL Injection autenticada","severity":"high","cvss":7.7,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N","cve":"CVE-2023-5940","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-5940","fixed_in":"1.11.26","source":"offline"},
                                                                               
    {"component":"file-manager","comp_type":"plugin","affects_lt":"6.9","title":"File Manager < 6.9 — RCE sin autenticación (ejecución de PHP arbitrario)","severity":"critical","cvss":10.0,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cve":"CVE-2020-25213","url":"https://nvd.nist.gov/vuln/detail/CVE-2020-25213","fixed_in":"6.9","kev":1,"source":"offline"},
                                                                               
    {"component":"bricks","comp_type":"plugin","affects_lt":"1.9.6.1","title":"Bricks Builder < 1.9.6.1 — RCE sin autenticación (CVSS 10)","severity":"critical","cvss":10.0,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cve":"CVE-2024-25600","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-25600","fixed_in":"1.9.6.1","kev":1,"source":"offline"},
                                                                               
    {"component":"wpdiscuz","comp_type":"plugin","affects_lt":"7.0.5","title":"wpDiscuz < 7.0.5 — RCE via subida de archivos sin autenticación","severity":"critical","cvss":10.0,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cve":"CVE-2020-24186","url":"https://nvd.nist.gov/vuln/detail/CVE-2020-24186","fixed_in":"7.0.5","kev":1,"source":"offline"},
                                                                               
    {"component":"all-in-one-wp-migration","comp_type":"plugin","affects_lt":"7.80","title":"All-in-One WP Migration < 7.80 — Subida de archivos sin restricción","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2024-27956","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-27956","fixed_in":"7.80","kev":1,"source":"offline"},
                                                                               
    {"component":"duplicator","comp_type":"plugin","affects_lt":"1.3.28","title":"Duplicator < 1.3.28 — LFI sin autenticación","severity":"critical","cvss":7.5,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","cve":"CVE-2020-11738","url":"https://nvd.nist.gov/vuln/detail/CVE-2020-11738","fixed_in":"1.3.28","kev":1,"source":"offline"},
                                                                               
    {"component":"forminator","comp_type":"plugin","affects_lt":"1.29.3","title":"Forminator < 1.29.3 — SQL Injection sin autenticación","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2024-28890","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-28890","fixed_in":"1.29.3","source":"offline"},
                                                                               
    {"component":"divi","comp_type":"theme","affects_lt":"4.23.0","title":"Divi Theme < 4.23 — XSS almacenado sin autenticación","severity":"high","cvss":7.2,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","cve":"CVE-2024-3413","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-3413","fixed_in":"4.23.0","source":"offline"},
                                                                               
    {"component":"avada","comp_type":"theme","affects_lt":"7.8.2","title":"Avada < 7.8.2 — SQL Injection en filtros de datos","severity":"high","cvss":8.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N","cve":"CVE-2023-28721","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-28721","fixed_in":"7.8.2","source":"offline"},
                                                                               
    {"component":"astra","comp_type":"theme","affects_lt":"3.9.2","title":"Astra Theme < 3.9.2 — XSS almacenado en customizer","severity":"medium","cvss":5.4,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N","cve":"CVE-2023-1671","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-1671","fixed_in":"3.9.2","source":"offline"},
                                                                               
    {"component":"jupiter","comp_type":"theme","affects_lt":"6.10.2","title":"Jupiter Theme < 6.10.2 — Escalada de privilegios sin autenticación","severity":"critical","cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cve":"CVE-2022-1654","url":"https://nvd.nist.gov/vuln/detail/CVE-2022-1654","fixed_in":"6.10.2","kev":1,"source":"offline"},
]

def _seed_offline(conn: sqlite3.Connection):
    """Carga los datos offline iniciales en la BD."""
    now = datetime.now().isoformat()
    for v in OFFLINE_SEED:
        v["updated_at"] = now
        v.setdefault("fixed_in", v.get("affects_lt", ""))
        upsert_vuln(conn, v)
    set_meta(conn, "last_update", now)
    set_meta(conn, "last_source", "offline-seed")
    conn.commit()
    log.info("Seed offline cargado: %d vulnerabilidades", len(OFFLINE_SEED))
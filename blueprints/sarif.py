"""
blueprints/sarif.py — Exportación SARIF para GitHub Advanced Security / GitLab SAST
====================================================================================
SARIF 2.1.0 — formato estándar OASIS para resultados de análisis de seguridad.
Compatible con: GitHub Advanced Security, GitLab SAST, VS Code SARIF Viewer,
                Microsoft SARIF Multitool, SonarQube.

Rutas:
  GET /scan/<job_id>/sarif      — descarga .sarif (JSON)
  GET /api/sarif/schema         — info del schema SARIF generado
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, Response, jsonify, request

from db import get_scan_from_db
from state import APP_VERSION, _validate_job_id, require_api_key, _jobs, _jobs_lock

log = logging.getLogger("wpvulnscan.sarif")

sarif_bp = Blueprint("sarif", __name__)

                                                                                
SARIF_VERSION  = "2.1.0"
SARIF_SCHEMA   = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_NAME      = "WP VulnScanner"
TOOL_VERSION   = APP_VERSION
TOOL_URL       = "https://github.com/wpvulnscan/wpvulnscan-pro"
TOOL_INFO_URI  = "https://nvd.nist.gov/vuln/detail/"

                                 
SEV_TO_LEVEL = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "none",
}

                                                                  
SEV_TO_SCORE = {
    "critical": "9.5",
    "high":     "7.5",
    "medium":   "5.0",
    "low":      "3.0",
    "info":     "1.0",
}


def _resolve_result(job_id: str):
    with _jobs_lock:
        entry = _jobs.get(job_id)
        if entry and entry.get("result"):
            return entry["result"]
    return get_scan_from_db(job_id)


def _build_rules(vulnerabilities: list, exposed_files: list,
                 headers_issues: list) -> list[dict]:
    """Construye la lista de reglas (rules) del driver SARIF."""
    rules: dict[str, dict] = {}

                               
    for v in vulnerabilities:
        if not isinstance(v, dict):
            continue
        rule_id = v.get("cve_id") or v.get("cve") or f"WPVS-{v.get('plugin_slug','unknown')}"
        if rule_id in rules:
            continue
        sev  = v.get("severity", "medium")
        cvss = v.get("cvss_score") or SEV_TO_SCORE.get(sev, "5.0")
        rules[rule_id] = {
            "id":   rule_id,
            "name": _to_camel(v.get("title", rule_id)),
            "shortDescription": {"text": v.get("title", rule_id)},
            "fullDescription":  {"text": v.get("description") or v.get("title", rule_id)},
            "helpUri": (TOOL_INFO_URI + rule_id) if rule_id.startswith("CVE-") else TOOL_URL,
            "help":   {"text": v.get("recommended_action") or f"Update {v.get('plugin_slug','')} to {v.get('fixed_in','latest')}.",
                       "markdown": _fix_markdown(v)},
            "defaultConfiguration": {"level": SEV_TO_LEVEL.get(sev, "warning")},
            "properties": {
                "tags":              ["wordpress", "plugin", sev],
                "security-severity": str(cvss),
                "precision":         "high",
                "problem.severity":  sev,
            },
        }

                             
    if exposed_files:
        rules["WPVS-EXPOSED-FILE"] = {
            "id":   "WPVS-EXPOSED-FILE",
            "name": "SensitiveFileExposed",
            "shortDescription": {"text": "Sensitive file publicly accessible"},
            "fullDescription":  {"text": "A sensitive file (config, backup, log) is accessible without authentication."},
            "helpUri": TOOL_URL,
            "help": {"text": "Remove or restrict access to sensitive files via server configuration."},
            "defaultConfiguration": {"level": "error"},
            "properties": {"tags": ["wordpress", "exposure"], "security-severity": "7.5"},
        }

                                   
    if headers_issues:
        rules["WPVS-MISSING-HEADER"] = {
            "id":   "WPVS-MISSING-HEADER",
            "name": "MissingSecurityHeader",
            "shortDescription": {"text": "Missing HTTP security header"},
            "fullDescription":  {"text": "A recommended HTTP security header is absent, increasing attack surface."},
            "helpUri": "https://owasp.org/www-project-secure-headers/",
            "help": {"text": "Add the missing header to your server or CDN configuration."},
            "defaultConfiguration": {"level": "warning"},
            "properties": {"tags": ["headers", "hardening"], "security-severity": "4.0"},
        }

    return list(rules.values())


def _build_results(scan_result: dict, target_url: str) -> list[dict]:
    """Construye la lista de resultados (results) del run SARIF."""
    sarif_results = []
    vulns        = scan_result.get("vulnerabilities", [])
    exposed      = scan_result.get("exposed_files", [])
    headers_bad  = scan_result.get("headers_issues", [])
    malware      = scan_result.get("malware_indicators", [])

                                                                                
    for v in vulns:
        if not isinstance(v, dict):
            continue
        rule_id  = v.get("cve_id") or v.get("cve") or f"WPVS-{v.get('plugin_slug','unknown')}"
        sev      = v.get("severity", "medium")
        slug     = v.get("plugin_slug") or v.get("component", "")
        version  = v.get("plugin_version") or v.get("version", "unknown")
        fixed_in = v.get("fixed_in", "")
        cvss     = v.get("cvss_score") or SEV_TO_SCORE.get(sev, "5.0")

        msg  = v.get("title", rule_id)
        if slug:
            msg += f" [{slug} v{version}]"
        if fixed_in:
            msg += f" — Fix available: update to v{fixed_in}"

        sarif_results.append({
            "ruleId":  rule_id,
            "level":   SEV_TO_LEVEL.get(sev, "warning"),
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": target_url, "uriBaseId": "%SRCROOT%"},
                    "region":           {"startLine": 1},
                },
                "logicalLocations": [{
                    "name":             slug or "wordpress",
                    "fullyQualifiedName": f"wordpress/{slug}" if slug else "wordpress",
                    "kind":             "package",
                }],
            }],
            "properties": {
                "severity":    sev,
                "cvssScore":   str(cvss),
                "component":   slug,
                "version":     version,
                "fixedIn":     fixed_in,
                "source":      v.get("source", "offline"),
            },
            "fingerprints": {
                "primaryLocationLineHash/v1": _fingerprint(rule_id, slug, version),
            },
            "partialFingerprints": {
                "primaryLocationLineHash": _fingerprint(rule_id, slug),
            },
        })

                                                                                
    for f in exposed:
        if not isinstance(f, dict):
            continue
        sev  = f.get("severity", "high")
        path = f.get("path", "")
        desc = f.get("description", "Sensitive file exposed")
        sarif_results.append({
            "ruleId":  "WPVS-EXPOSED-FILE",
            "level":   SEV_TO_LEVEL.get(sev, "error"),
            "message": {"text": f"{desc}: {path}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri":       (target_url.rstrip("/") + path),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": 1},
                },
            }],
            "properties": {"severity": sev, "path": path},
            "fingerprints": {"primaryLocationLineHash/v1": _fingerprint("EXPOSED", path)},
        })

                                                                                
    for header in headers_bad:
        sarif_results.append({
            "ruleId":  "WPVS-MISSING-HEADER",
            "level":   "warning",
            "message": {"text": f"Missing security header: {header}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": target_url, "uriBaseId": "%SRCROOT%"},
                    "region":           {"startLine": 1},
                },
            }],
            "properties": {"header": header},
            "fingerprints": {"primaryLocationLineHash/v1": _fingerprint("HEADER", header)},
        })

                                                                                
    for indicator in malware:
        sarif_results.append({
            "ruleId":  "WPVS-MALWARE",
            "level":   "error",
            "message": {"text": f"Malware indicator detected: {indicator}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": target_url, "uriBaseId": "%SRCROOT%"},
                    "region":           {"startLine": 1},
                },
            }],
            "properties": {"indicator": str(indicator)},
            "fingerprints": {"primaryLocationLineHash/v1": _fingerprint("MALWARE", str(indicator))},
        })

    return sarif_results


def build_sarif(scan_result: dict, job_id: str) -> dict:
    """Construye el documento SARIF 2.1.0 completo."""
    target_url   = scan_result.get("target_url", "https://unknown")
    scanned_at   = scan_result.get("scanned_at", datetime.now().isoformat())
    vulns        = scan_result.get("vulnerabilities", [])
    exposed      = scan_result.get("exposed_files", [])
    headers_bad  = scan_result.get("headers_issues", [])
    risk_score   = scan_result.get("risk_score", 0)

    rules   = _build_rules(vulns, exposed, headers_bad)
    results = _build_results(scan_result, target_url)

                                                
    if scan_result.get("malware_indicators"):
        rules.append({
            "id":   "WPVS-MALWARE",
            "name": "MalwareIndicatorDetected",
            "shortDescription": {"text": "Malware or SEO spam indicator"},
            "fullDescription":  {"text": "A script, link or content pattern associated with malware or SEO spam was found."},
            "helpUri": TOOL_URL,
            "help": {"text": "Investigate and clean the affected WordPress installation."},
            "defaultConfiguration": {"level": "error"},
            "properties": {"tags": ["malware", "wordpress"], "security-severity": "9.0"},
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name":           TOOL_NAME,
                    "version":        TOOL_VERSION,
                    "informationUri": TOOL_URL,
                    "semanticVersion": TOOL_VERSION,
                    "rules":          rules,
                    "properties": {
                        "targetUrl":  target_url,
                        "scanId":     job_id,
                        "riskScore":  risk_score,
                        "riskLabel":  scan_result.get("risk_label", ""),
                        "wpVersion":  scan_result.get("wp_version", ""),
                        "scannedAt":  scanned_at,
                    },
                }
            },
            "originalUriBaseIds": {
                "%SRCROOT%": {"uri": target_url if target_url.endswith("/") else target_url + "/"},
            },
            "results":   results,
            "artifacts": [{
                "location": {"uri": target_url, "uriBaseId": "%SRCROOT%"},
                "description": {"text": f"WordPress site scanned at {scanned_at}"},
                "roles":    ["scannedFile"],
                "mimeType": "text/html",
                "properties": {
                    "wordpressVersion": scan_result.get("wp_version"),
                    "phpVersion":       scan_result.get("php_version"),
                    "server":           scan_result.get("server_info"),
                },
            }],
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": _to_utc(scanned_at),
                "endTimeUtc":   _to_utc(scanned_at),
                "toolExecutionNotifications": [],
                "properties": {
                    "scanDurationSeconds": scan_result.get("duration", 0),
                    "wpscanApiUsed":       scan_result.get("wpscan_api_used", False),
                    "xmlrpcEnabled":       scan_result.get("xmlrpc_enabled", False),
                    "loginExposed":        scan_result.get("login_exposed", False),
                },
            }],
            "properties": {
                "summary":     scan_result.get("summary", {}),
                "riskScore":   risk_score,
                "riskLabel":   scan_result.get("risk_label", ""),
                "scanId":      job_id,
                "generatedBy": f"{TOOL_NAME} v{TOOL_VERSION}",
            },
        }],
    }


                                                                                

def _fingerprint(*parts: str) -> str:
    """Hash corto estable para fingerprint de hallazgo."""
    import hashlib
    combined = "|".join(str(p) for p in parts if p)
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


def _to_camel(text: str) -> str:
    """Convierte un título a CamelCase para el name de la regla."""
    words = "".join(c if c.isalnum() or c == " " else " " for c in text).split()
    return "".join(w.capitalize() for w in words[:6]) or "UnknownVulnerability"


def _to_utc(date_str: str) -> str:
    """Convierte fecha de BD a formato UTC ISO 8601 para SARIF."""
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d/%m/%Y %H:%M:%S"):
        try:
            dt = datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    return datetime.now(timezone.utc).isoformat()


def _fix_markdown(v: dict) -> str:
    """Genera texto de ayuda en Markdown para la regla."""
    lines = [f"## {v.get('title', 'Vulnerability')}"]
    if v.get("description"):
        lines.append(f"\n{v['description']}")
    if v.get("fixed_in"):
        lines.append(f"\n**Fix:** Update to version `{v['fixed_in']}` or later.")
    if v.get("cve_id") or v.get("cve"):
        cve = v.get("cve_id") or v.get("cve")
        lines.append(f"\n**CVE:** [{cve}](https://nvd.nist.gov/vuln/detail/{cve})")
    if v.get("cvss_score"):
        lines.append(f"\n**CVSS Score:** {v['cvss_score']}")
    return "\n".join(lines)


                                                                                

@sarif_bp.route("/scan/<job_id>/sarif")
@require_api_key
def download_sarif(job_id: str):
    """
    Exporta el resultado en formato SARIF 2.1.0.
    Compatible con GitHub Advanced Security, GitLab SAST y VS Code SARIF Viewer.
    """
    if not _validate_job_id(job_id):
        return jsonify({"error": "job_id inválido"}), 400

    result = _resolve_result(job_id)
    if not result:
        return jsonify({"error": "Escaneo no encontrado"}), 404

    try:
        sarif_doc = build_sarif(result, job_id)
    except Exception as e:
        log.error("Error generando SARIF %s: %s", job_id, e, exc_info=True)
        return jsonify({"error": f"Error generando SARIF: {e}"}), 500

    domain = (result.get("target_url") or "").split("//")[-1].split("/")[0]
    fname  = f"wpvuln-{domain}-{job_id[:6]}.sarif"

    return Response(
        json.dumps(sarif_doc, ensure_ascii=False, indent=2),
        mimetype="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{fname}"',
            "X-SARIF-Version":     SARIF_VERSION,
        },
    )


@sarif_bp.route("/api/sarif/schema")
def sarif_schema_info():
    """Info del schema SARIF generado por esta herramienta."""
    return jsonify({
        "sarif_version":    SARIF_VERSION,
        "schema_url":       SARIF_SCHEMA,
        "tool":             TOOL_NAME,
        "tool_version":     TOOL_VERSION,
        "supported_rules":  ["CVE-*", "WPVS-EXPOSED-FILE", "WPVS-MISSING-HEADER", "WPVS-MALWARE"],
        "compatible_with":  [
            "GitHub Advanced Security",
            "GitLab SAST",
            "VS Code SARIF Viewer",
            "Microsoft SARIF Multitool",
            "SonarQube (via plugin)",
        ],
        "usage": {
            "endpoint":    "/scan/{job_id}/sarif",
            "method":      "GET",
            "auth":        "X-API-Key header (if API_KEY configured)",
            "github_docs": "https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github",
        },
    })

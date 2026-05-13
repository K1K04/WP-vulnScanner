"""
blueprints/vulns.py — Navegador de base de datos de vulnerabilidades
"""
from __future__ import annotations
import logging
from flask import Blueprint, jsonify, render_template, request
from state import API_KEY, _int

log = logging.getLogger("wpvulnscan.vulns")
vulns_bp = Blueprint("vulns", __name__)


@vulns_bp.route("/vulns-db")
def vulns_db_page():
    return render_template("vulns_db.html", api_key=API_KEY)


@vulns_bp.route("/api/vulns")
def api_vulns():
    q          = request.args.get("q", "").strip()
    cve        = request.args.get("cve", "").strip()
    component  = request.args.get("component", "").strip()
    severity   = request.args.get("severity", "").strip().lower()
    limit      = _int(request.args.get("limit", 50), 50, 0, 5000)

    from scanner.vulns_db import get_conn as vdb_conn
    try:
        conn   = vdb_conn()
        wheres = []
        params = []

        if q:
            wheres.append("(title LIKE ? OR description LIKE ? OR component LIKE ?)")
            params += [f"%{q}%", f"%{q}%", f"%{q}%"]
        if cve:
            wheres.append("cve LIKE ?")
            params.append(f"%{cve}%")
        if component:
            wheres.append("component LIKE ?")
            params.append(f"%{component}%")
        if severity and severity in ("critical", "high", "medium", "low", "info"):
            wheres.append("severity = ?")
            params.append(severity)

        where_sql = ("WHERE " + " AND ".join(wheres)) if wheres else ""
        rows = conn.execute(
            f"""SELECT id, component, comp_type, title, severity, cvss,
                       cve, fixed_in, url, source, updated_at
                FROM vulnerabilities {where_sql}
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4
                    END,
                    cvss DESC NULLS LAST
                LIMIT ?""",
            params + [limit]
        ).fetchall()
        total = conn.execute(
            f"SELECT COUNT(*) FROM vulnerabilities {where_sql}", params
        ).fetchone()[0]
        conn.close()

        def _normalize(r):
            d = dict(r)
            d["cve_id"]         = d.get("cve") or ""
            d["component_slug"] = d.get("component") or ""
            d["component_type"] = d.get("comp_type") or ""
            d["cvss_score"]     = d.get("cvss")
            d["published"]      = d.get("updated_at") or ""
            return d

        return jsonify({"results": [_normalize(r) for r in rows],
                        "vulns":   [_normalize(r) for r in rows],
                        "total":   total, "limit": limit})
    except Exception:
        return jsonify({"error": "Error consultando vulnerabilidades"}), 500


@vulns_bp.route("/api/vulns/<cve_id>")
def api_vuln_detail(cve_id: str):
    from scanner.vulns_db import get_conn as vdb_conn
    try:
        conn = vdb_conn()
        rows = conn.execute(
            "SELECT * FROM vulnerabilities WHERE cve LIKE ? ORDER BY updated_at DESC",
            (f"%{cve_id}%",)
        ).fetchall()
        conn.close()
        if not rows:
            return jsonify({"error": f"CVE {cve_id} no encontrada"}), 404
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        log.error("api_vuln_detail error: %s", e)
        return jsonify({"error": "Error obteniendo detalle de CVE"}), 500

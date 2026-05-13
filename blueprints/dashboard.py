"""
blueprints/dashboard.py — Dashboard y KPIs globales
"""
from __future__ import annotations

import json
import logging
import sqlite3
from flask import Blueprint, jsonify, render_template, request

from state import (API_KEY, DB_PATH, _int, require_api_key,
                   top_plugins_cache_get, top_plugins_cache_set)

log = logging.getLogger("wpvulnscan.dashboard")

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", api_key=API_KEY)


@dashboard_bp.route("/api/dashboard")
@require_api_key
def api_dashboard():
    limit  = _int(request.args.get("limit", 50), 50, 0, 200)
    offset = _int(request.args.get("offset", 0), 0, 0, 100_000)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
                                                                              
        def _q(sql, params=()):
            try:
                return conn.execute(sql, params)
            except sqlite3.OperationalError as _e:
                log.warning("dashboard query skipped (%s): %s", _e, sql[:60])
                return None

        def _scalar(sql, default=0, params=()):
            r = _q(sql, params)
            if r is None:
                return default
            row = r.fetchone()
            return (row[0] if row and row[0] is not None else default)

        def _rows(sql, params=()):
            r = _q(sql, params)
            return r.fetchall() if r else []

        total          = _scalar("SELECT COUNT(*) FROM scans")
        by_risk        = _rows("SELECT risk_label, COUNT(*) as cnt FROM scans GROUP BY risk_label")
        top_vulns      = _rows("SELECT url, risk_score, risk_label, vuln_count, scanned_at FROM scans ORDER BY risk_score DESC LIMIT 10")
        recent         = _rows("""
            SELECT id, url, risk_score, risk_label, vuln_count, critical_count,
                   high_count, plugin_count, exposed_count, users_count,
                   scanned_at, wpscan_api, duration, wp_version
            FROM scans ORDER BY scanned_at DESC LIMIT ? OFFSET ?
        """, (limit, offset))
        avg_risk       = _scalar("SELECT AVG(risk_score) FROM scans")
        avg_vulns      = _scalar("SELECT AVG(vuln_count) FROM scans")
        total_vulns    = _scalar("SELECT SUM(vuln_count) FROM scans")
        total_critical = _scalar("SELECT SUM(critical_count) FROM scans")
        total_high     = _scalar("SELECT SUM(high_count) FROM scans")
        wpscan_count   = _scalar("SELECT COUNT(*) FROM scans WHERE wpscan_api=1")
        trend          = _rows("SELECT scanned_at, risk_score, risk_label FROM scans ORDER BY scanned_at DESC LIMIT 30")

        top_domains = _rows("""
            SELECT url, MAX(risk_score) AS peak_risk, COUNT(*) AS scan_count,
                   AVG(risk_score) AS avg_risk, MAX(vuln_count) AS max_vulns,
                   MAX(scanned_at) AS last_scan
            FROM scans GROUP BY url ORDER BY peak_risk DESC, avg_risk DESC LIMIT 5
        """)

                       
        domain_trend_rows = _rows("SELECT url, scanned_at, risk_score FROM scans ORDER BY url, scanned_at DESC")
        domain_trends: dict = {}
        for row in domain_trend_rows:
            u = row["url"]
            if u not in domain_trends:
                domain_trends[u] = []
            if len(domain_trends[u]) < 8:
                domain_trends[u].append({"date": row["scanned_at"], "score": row["risk_score"]})
        domain_trends_out = [
            {"url": uk, "points": list(reversed(pts))}
            for uk, pts in domain_trends.items() if len(pts) >= 2
        ]
        domain_trends_out.sort(key=lambda x: x["points"][-1]["score"] if x["points"] else 0, reverse=True)

                                                                               
                                                                              
                                                                    
        top_plugins_list = top_plugins_cache_get()
        if top_plugins_list is None:
            top_plugins: dict = {}
            all_jsons = conn.execute(
                "SELECT result_json FROM scans WHERE result_json IS NOT NULL AND vuln_count > 0 ORDER BY scanned_at DESC LIMIT 100"
            ).fetchall()
            for row in all_jsons:
                try:
                    rd = json.loads(row[0])
                    for v in rd.get("vulnerabilities", []):
                        if not isinstance(v, dict):
                            continue
                        slug = v.get("plugin_slug") or v.get("component_slug") or ""
                        if not slug:
                            continue
                        if slug not in top_plugins:
                            top_plugins[slug] = {"slug": slug, "vuln_count": 0, "severities": {}}
                        top_plugins[slug]["vuln_count"] += 1
                        sev = v.get("severity", "low")
                        top_plugins[slug]["severities"][sev] = top_plugins[slug]["severities"].get(sev, 0) + 1
                except Exception as e:
                    log.debug("dashboard top_plugins loop: %s", e)
            top_plugins_list = sorted(top_plugins.values(), key=lambda x: x["vuln_count"], reverse=True)[:10]
            top_plugins_cache_set(top_plugins_list)

                         
        heatmap_rows = conn.execute("SELECT scanned_at, risk_score FROM scans ORDER BY scanned_at DESC LIMIT 500").fetchall()
        heatmap = [{"day": i, "count": 0, "total_risk": 0} for i in range(7)]
        import re as _re
        from datetime import date as _date
        for row in heatmap_rows:
            try:
                sa = row["scanned_at"] or ""
                for _fmt, _pat in [
                    ("%Y-%m-%d", r"(\d{4})-(\d{2})-(\d{2})"),
                    ("%d/%m/%Y", r"(\d{2})/(\d{2})/(\d{4})"),
                ]:
                    m = _re.match(_pat, sa)
                    if m:
                        try:
                            if _fmt == "%Y-%m-%d":
                                d = _date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
                            else:
                                d = _date(int(m.group(3)), int(m.group(2)), int(m.group(1)))
                            heatmap[d.weekday()]["count"] += 1
                            heatmap[d.weekday()]["total_risk"] += (row["risk_score"] or 0)
                        except Exception as _e:
                            try:
                                log.debug("dashboard heatmap date parse suppressed: %s", _e)
                            except Exception:
                                pass
                        break
            except Exception as _e:
                try:
                    log.debug("dashboard heatmap outer parse suppressed: %s", _e)
                except Exception:
                    pass

        heatmap_out = [
            {"day": ["Lun","Mar","Mié","Jue","Vie","Sáb","Dom"][i],
             "count": h["count"],
             "avg_risk": round(h["total_risk"] / h["count"], 1) if h["count"] else 0}
            for i, h in enumerate(heatmap)
        ]

    finally:
        conn.close()

    return jsonify({
        "total_scans":      total,
        "avg_risk":         round(avg_risk, 1),
        "avg_vulns":        round(avg_vulns, 1),
        "total_vulns":      total_vulns,
        "total_critical":   total_critical,
        "total_high":       total_high,
        "wpscan_api_count": wpscan_count,
        "by_risk":          [dict(r) for r in by_risk],
        "top_risky":        [dict(r) for r in top_vulns],
        "recent":           [dict(r) for r in recent],
        "trend":            [dict(r) for r in trend],
        "top_domains":      [dict(r) for r in top_domains],
        "domain_trends":    domain_trends_out[:5],
        "top_plugins":      top_plugins_list,
        "heatmap":          heatmap_out,
        "limit":            limit,
        "offset":           offset,
        "has_next":         (offset + limit) < total,
    })


@dashboard_bp.route("/api/dashboard/domain-trend")
def api_domain_trend():
    url   = request.args.get("url", "").strip()
    limit = _int(request.args.get("limit", 20), 20, 0, 50)
    if not url:
        return jsonify({"error": "url requerido"}), 400
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("""
            SELECT scanned_at, risk_score, risk_label, vuln_count, id
            FROM scans WHERE url LIKE ?
            ORDER BY scanned_at DESC LIMIT ?
        """, (f"%{url}%", limit)).fetchall()
    finally:
        conn.close()
    return jsonify({"points": [dict(r) for r in reversed(rows)]})

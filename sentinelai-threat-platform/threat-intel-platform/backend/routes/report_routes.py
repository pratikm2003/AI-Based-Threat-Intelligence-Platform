"""
report_routes.py
-------------------
Date-range based reporting and CSV export. Lets the user pick 7 / 30 /
90 days (or all time) and get a breakdown plus a downloadable CSV.
"""

import csv
import io
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, Response

from database import get_db_connection
from utils import login_required, error_response

report_bp = Blueprint("reports", __name__, url_prefix="/api/reports")

RANGE_DAYS = {"7d": 7, "30d": 30, "90d": 90, "all": None}


def _range_cutoff(range_key):
    days = RANGE_DAYS.get(range_key)
    if days is None:
        return None
    return (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


@report_bp.route("/summary", methods=["GET"])
@login_required
def report_summary():
    range_key = request.args.get("range", "30d")
    if range_key not in RANGE_DAYS:
        return error_response("range must be one of: 7d, 30d, 90d, all")

    cutoff = _range_cutoff(range_key)
    where_sql = "WHERE detected_at >= ?" if cutoff else ""
    params = [cutoff] if cutoff else []

    conn = get_db_connection()
    try:
        total = conn.execute(
            f"SELECT COUNT(*) c FROM threats {where_sql}", params
        ).fetchone()["c"]

        severity_rows = conn.execute(
            f"SELECT severity, COUNT(*) c FROM threats {where_sql} GROUP BY severity", params
        ).fetchall()
        severity_counts = {r["severity"]: r["c"] for r in severity_rows}
        for s in ["low", "medium", "high", "critical"]:
            severity_counts.setdefault(s, 0)

        type_rows = conn.execute(
            f"""SELECT threat_type, COUNT(*) c FROM threats {where_sql}
                GROUP BY threat_type ORDER BY c DESC""",
            params,
        ).fetchall()
        type_breakdown = [
            {"type": r["threat_type"], "count": r["c"],
             "percentage": round((r["c"] / total) * 100, 1) if total else 0}
            for r in type_rows
        ]

        ioc_rows = conn.execute(
            f"SELECT ioc_type, COUNT(*) c FROM threats {where_sql} GROUP BY ioc_type ORDER BY c DESC",
            params,
        ).fetchall()
        ioc_breakdown = [{"ioc_type": r["ioc_type"], "count": r["c"]} for r in ioc_rows]

        source_rows = conn.execute(
            f"""SELECT source, COUNT(*) c FROM threats {where_sql}
                GROUP BY source ORDER BY c DESC LIMIT 5""",
            params,
        ).fetchall()
        top_sources = [{"source": r["source"] or "Unknown", "count": r["c"]} for r in source_rows]

        trend_rows = conn.execute(
            f"""SELECT substr(detected_at,1,10) as day, COUNT(*) c FROM threats {where_sql}
                GROUP BY day ORDER BY day ASC""",
            params,
        ).fetchall()
        trend = [{"date": r["day"], "count": r["c"]} for r in trend_rows]

        analyses_total = conn.execute(
            f"""SELECT COUNT(*) c FROM analysis_logs
                {"WHERE analyzed_at >= ?" if cutoff else ""}""",
            params,
        ).fetchone()["c"]

    finally:
        conn.close()

    return jsonify({
        "range": range_key,
        "total_threats": total,
        "severity_counts": severity_counts,
        "type_breakdown": type_breakdown,
        "ioc_breakdown": ioc_breakdown,
        "top_sources": top_sources,
        "trend": trend,
        "total_analyses": analyses_total,
    })


@report_bp.route("/export", methods=["GET"])
@login_required
def export_csv():
    range_key = request.args.get("range", "all")
    if range_key not in RANGE_DAYS:
        return error_response("range must be one of: 7d, 30d, 90d, all")

    cutoff = _range_cutoff(range_key)
    where_sql = "WHERE t.detected_at >= ?" if cutoff else ""
    params = [cutoff] if cutoff else []

    conn = get_db_connection()
    try:
        rows = conn.execute(
            f"""SELECT t.id, t.ioc_value, t.ioc_type, t.threat_type, t.severity,
                       t.confidence_score, t.status, t.description, t.source,
                       t.detected_at, u.username as created_by
                FROM threats t LEFT JOIN users u ON t.created_by = u.id
                {where_sql}
                ORDER BY t.detected_at DESC""",
            params,
        ).fetchall()
    finally:
        conn.close()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["ID", "IOC Value", "IOC Type", "Threat Type", "Severity",
                      "Confidence Score", "Status", "Description", "Source",
                      "Detected At", "Created By"])
    for r in rows:
        writer.writerow([r["id"], r["ioc_value"], r["ioc_type"], r["threat_type"],
                          r["severity"], r["confidence_score"], r["status"],
                          r["description"] or "", r["source"] or "",
                          r["detected_at"], r["created_by"] or "system"])

    filename = f"sentinelai_threat_report_{range_key}.csv"
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

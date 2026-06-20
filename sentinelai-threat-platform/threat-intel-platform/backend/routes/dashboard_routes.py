"""
dashboard_routes.py
---------------------
Aggregate statistics for the dashboard home page: stat cards, the
14-day trend line chart, the threat-type donut chart, and the recent
threats table.
"""

from datetime import datetime, timedelta
from flask import Blueprint, jsonify

from database import get_db_connection, rows_to_list
from utils import login_required

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


@dashboard_bp.route("/summary", methods=["GET"])
@login_required
def summary():
    conn = get_db_connection()
    try:
        total_threats = conn.execute("SELECT COUNT(*) c FROM threats").fetchone()["c"]

        severity_rows = conn.execute(
            "SELECT severity, COUNT(*) c FROM threats GROUP BY severity"
        ).fetchall()
        severity_counts = {row["severity"]: row["c"] for row in severity_rows}
        for s in ["low", "medium", "high", "critical"]:
            severity_counts.setdefault(s, 0)

        status_rows = conn.execute(
            "SELECT status, COUNT(*) c FROM threats GROUP BY status"
        ).fetchall()
        status_counts = {row["status"]: row["c"] for row in status_rows}
        for s in ["active", "investigating", "resolved"]:
            status_counts.setdefault(s, 0)

        type_rows = conn.execute(
            "SELECT threat_type, COUNT(*) c FROM threats GROUP BY threat_type ORDER BY c DESC"
        ).fetchall()
        type_distribution = [{"type": r["threat_type"], "count": r["c"]} for r in type_rows]

        # Last 14 days trend (including days with zero threats)
        since = (datetime.utcnow() - timedelta(days=13)).strftime("%Y-%m-%d")
        trend_rows = conn.execute(
            """SELECT substr(detected_at, 1, 10) as day, COUNT(*) c
               FROM threats
               WHERE substr(detected_at, 1, 10) >= ?
               GROUP BY day ORDER BY day ASC""",
            (since,),
        ).fetchall()
        trend_map = {r["day"]: r["c"] for r in trend_rows}
        trend = []
        for i in range(13, -1, -1):
            day = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
            trend.append({"date": day, "count": trend_map.get(day, 0)})

        recent_rows = conn.execute(
            """SELECT t.*, u.username as created_by_username
               FROM threats t LEFT JOIN users u ON t.created_by = u.id
               ORDER BY t.detected_at DESC LIMIT 6"""
        ).fetchall()

        total_analyses = conn.execute("SELECT COUNT(*) c FROM analysis_logs").fetchone()["c"]
        total_users = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]

        ai_flagged = conn.execute(
            "SELECT COUNT(*) c FROM analysis_logs WHERE prediction = 'malicious' AND matched_existing_threat = 0"
        ).fetchone()["c"]

    finally:
        conn.close()

    return jsonify({
        "total_threats": total_threats,
        "severity_counts": severity_counts,
        "status_counts": status_counts,
        "type_distribution": type_distribution,
        "trend_14_days": trend,
        "recent_threats": rows_to_list(recent_rows),
        "total_analyses": total_analyses,
        "ai_flagged_malicious": ai_flagged,
        "total_users": total_users,
    })

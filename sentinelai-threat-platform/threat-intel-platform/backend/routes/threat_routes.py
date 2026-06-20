"""
threat_routes.py
------------------
CRUD endpoints for the core threat_intelligence data: IOC records.
Supports search, filtering by severity/type/status, and pagination -
the things a real threat intel feed needs.
"""

from flask import Blueprint, request, jsonify, session

import config
from database import get_db_connection, rows_to_list, row_to_dict
from utils import login_required, admin_required, error_response

threat_bp = Blueprint("threats", __name__, url_prefix="/api/threats")


@threat_bp.route("", methods=["GET"])
@login_required
def list_threats():
    search = (request.args.get("search") or "").strip()
    severity = request.args.get("severity") or ""
    threat_type = request.args.get("threat_type") or ""
    status = request.args.get("status") or ""
    try:
        page = max(int(request.args.get("page", 1)), 1)
        per_page = min(max(int(request.args.get("per_page", 10)), 1), 100)
    except ValueError:
        return error_response("page and per_page must be integers.")

    where_clauses = []
    params = []

    if search:
        where_clauses.append("(ioc_value LIKE ? OR description LIKE ? OR source LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like])
    if severity and severity in config.SEVERITIES:
        where_clauses.append("severity = ?")
        params.append(severity)
    if threat_type and threat_type in config.THREAT_TYPES:
        where_clauses.append("threat_type = ?")
        params.append(threat_type)
    if status and status in config.STATUSES:
        where_clauses.append("status = ?")
        params.append(status)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    conn = get_db_connection()
    try:
        total = conn.execute(
            f"SELECT COUNT(*) as cnt FROM threats {where_sql}", params
        ).fetchone()["cnt"]

        offset = (page - 1) * per_page
        rows = conn.execute(
            f"""SELECT t.*, u.username as created_by_username
                FROM threats t LEFT JOIN users u ON t.created_by = u.id
                {where_sql}
                ORDER BY t.detected_at DESC
                LIMIT ? OFFSET ?""",
            params + [per_page, offset],
        ).fetchall()
    finally:
        conn.close()

    return jsonify({
        "threats": rows_to_list(rows),
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": max((total + per_page - 1) // per_page, 1),
    })


@threat_bp.route("/<int:threat_id>", methods=["GET"])
@login_required
def get_threat(threat_id):
    conn = get_db_connection()
    try:
        row = conn.execute(
            """SELECT t.*, u.username as created_by_username
               FROM threats t LEFT JOIN users u ON t.created_by = u.id
               WHERE t.id = ?""",
            (threat_id,),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return error_response("Threat record not found.", 404)
    return jsonify({"threat": row_to_dict(row)})


@threat_bp.route("", methods=["POST"])
@login_required
def create_threat():
    data = request.get_json(silent=True) or {}

    ioc_value = (data.get("ioc_value") or "").strip()
    ioc_type = data.get("ioc_type") or ""
    threat_type = data.get("threat_type") or ""
    severity = data.get("severity") or ""
    description = (data.get("description") or "").strip()
    source = (data.get("source") or "Manual Entry").strip()

    try:
        confidence_score = int(data.get("confidence_score", 50))
    except (ValueError, TypeError):
        return error_response("confidence_score must be a number between 0 and 100.")

    if not ioc_value:
        return error_response("ioc_value is required.")
    if ioc_type not in config.IOC_TYPES:
        return error_response(f"ioc_type must be one of: {', '.join(config.IOC_TYPES)}")
    if threat_type not in config.THREAT_TYPES:
        return error_response(f"threat_type must be one of: {', '.join(config.THREAT_TYPES)}")
    if severity not in config.SEVERITIES:
        return error_response(f"severity must be one of: {', '.join(config.SEVERITIES)}")
    if not (0 <= confidence_score <= 100):
        return error_response("confidence_score must be between 0 and 100.")

    conn = get_db_connection()
    try:
        cursor = conn.execute(
            """INSERT INTO threats
               (ioc_value, ioc_type, threat_type, severity, confidence_score,
                description, source, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (ioc_value, ioc_type, threat_type, severity, confidence_score,
             description, source, session["user_id"]),
        )
        conn.commit()
        new_id = cursor.lastrowid
        row = conn.execute("SELECT * FROM threats WHERE id = ?", (new_id,)).fetchone()
    finally:
        conn.close()

    return jsonify({"message": "Threat record created.", "threat": row_to_dict(row)}), 201


@threat_bp.route("/<int:threat_id>", methods=["PUT"])
@login_required
def update_threat(threat_id):
    data = request.get_json(silent=True) or {}

    conn = get_db_connection()
    try:
        existing = conn.execute("SELECT * FROM threats WHERE id = ?", (threat_id,)).fetchone()
        if not existing:
            return error_response("Threat record not found.", 404)

        updates = {}
        if "status" in data:
            if data["status"] not in config.STATUSES:
                return error_response(f"status must be one of: {', '.join(config.STATUSES)}")
            updates["status"] = data["status"]
        if "severity" in data:
            if data["severity"] not in config.SEVERITIES:
                return error_response(f"severity must be one of: {', '.join(config.SEVERITIES)}")
            updates["severity"] = data["severity"]
        if "description" in data:
            updates["description"] = (data["description"] or "").strip()
        if "confidence_score" in data:
            try:
                cs = int(data["confidence_score"])
            except (ValueError, TypeError):
                return error_response("confidence_score must be a number.")
            if not (0 <= cs <= 100):
                return error_response("confidence_score must be between 0 and 100.")
            updates["confidence_score"] = cs

        if not updates:
            return error_response("No valid fields supplied to update.")

        set_sql = ", ".join(f"{k} = ?" for k in updates)
        params = list(updates.values()) + [threat_id]
        conn.execute(f"UPDATE threats SET {set_sql} WHERE id = ?", params)
        conn.commit()

        row = conn.execute("SELECT * FROM threats WHERE id = ?", (threat_id,)).fetchone()
    finally:
        conn.close()

    return jsonify({"message": "Threat record updated.", "threat": row_to_dict(row)})


@threat_bp.route("/<int:threat_id>", methods=["DELETE"])
@admin_required
def delete_threat(threat_id):
    conn = get_db_connection()
    try:
        existing = conn.execute("SELECT id FROM threats WHERE id = ?", (threat_id,)).fetchone()
        if not existing:
            return error_response("Threat record not found.", 404)
        conn.execute("DELETE FROM threats WHERE id = ?", (threat_id,))
        conn.commit()
    finally:
        conn.close()

    return jsonify({"message": "Threat record deleted."})

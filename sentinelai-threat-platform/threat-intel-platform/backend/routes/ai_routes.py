"""
ai_routes.py
-------------
The AI-powered analysis endpoints. This is the heart of the "AI-based"
part of the platform.

Workflow for /url:
    1. First check if the exact IOC already exists in our own threat
       database (a real intel platform always prefers a known,
       analyst-confirmed verdict over a fresh model guess).
    2. If not found, run the trained ML model (url_classifier) to score it.
    3. Log every analysis to analysis_logs for the history/audit trail.
"""

import json
from flask import Blueprint, request, jsonify, session

from database import get_db_connection, rows_to_list
from utils import login_required, error_response
from ai_engine.url_classifier import predict_url
from ai_engine.text_classifier import predict_text

ai_bp = Blueprint("ai", __name__, url_prefix="/api/analyze")


@ai_bp.route("/url", methods=["POST"])
@login_required
def analyze_url():
    data = request.get_json(silent=True) or {}
    raw_input = (data.get("url") or "").strip()
    if not raw_input:
        return error_response("Please provide a URL, domain, or IP address to analyze.")
    if len(raw_input) > 2000:
        return error_response("Input is too long.")

    conn = get_db_connection()
    try:
        existing = conn.execute(
            "SELECT * FROM threats WHERE ioc_value = ? COLLATE NOCASE LIMIT 1",
            (raw_input,),
        ).fetchone()

        if existing:
            result = {
                "input": raw_input,
                "verdict": "malicious" if existing["severity"] in ("high", "critical") else "suspicious",
                "confidence": float(existing["confidence_score"]),
                "source": "threat_database",
                "matched_existing_threat": True,
                "existing_record": dict(existing),
                "risk_factors": [
                    f"This indicator is already recorded in the threat database as '{existing['threat_type']}'",
                    f"Reported severity: {existing['severity']}",
                    f"Source: {existing['source'] or 'Unknown'}",
                ],
            }
            conn.execute(
                """INSERT INTO analysis_logs
                   (input_type, input_value, prediction, confidence, risk_factors,
                    matched_existing_threat, analyzed_by)
                   VALUES (?, ?, ?, ?, ?, 1, ?)""",
                ("url", raw_input, result["verdict"], result["confidence"],
                 json.dumps(result["risk_factors"]), session["user_id"]),
            )
            conn.commit()
            return jsonify({"result": result})

        # Not a known IOC -> ask the trained ML model
        ml_result = predict_url(raw_input)
        result = {
            "input": raw_input,
            "verdict": ml_result["verdict"],
            "confidence": ml_result["confidence"],
            "malicious_probability": ml_result["malicious_probability"],
            "source": "ai_model",
            "matched_existing_threat": False,
            "risk_factors": ml_result["risk_factors"],
            "features": ml_result["features"],
            "model_test_accuracy": ml_result["model_test_accuracy"],
        }
        conn.execute(
            """INSERT INTO analysis_logs
               (input_type, input_value, prediction, confidence, risk_factors,
                matched_existing_threat, analyzed_by)
               VALUES (?, ?, ?, ?, ?, 0, ?)""",
            ("url", raw_input, result["verdict"], result["confidence"],
             json.dumps(result["risk_factors"]), session["user_id"]),
        )
        conn.commit()
        return jsonify({"result": result})
    finally:
        conn.close()


@ai_bp.route("/text", methods=["POST"])
@login_required
def analyze_text():
    data = request.get_json(silent=True) or {}
    description = (data.get("description") or "").strip()
    if not description:
        return error_response("Please provide a description of the incident to classify.")
    if len(description) > 3000:
        return error_response("Description is too long (max 3000 characters).")

    ml_result = predict_text(description)
    result = {
        "input": description,
        "predicted_category": ml_result["predicted_category"],
        "confidence": ml_result["confidence"],
        "top_categories": ml_result["top_categories"],
        "model_test_accuracy": ml_result["model_test_accuracy"],
    }

    conn = get_db_connection()
    try:
        conn.execute(
            """INSERT INTO analysis_logs
               (input_type, input_value, prediction, confidence, risk_factors,
                matched_existing_threat, analyzed_by)
               VALUES (?, ?, ?, ?, ?, 0, ?)""",
            ("text", description, ml_result["predicted_category"], ml_result["confidence"],
             json.dumps(ml_result["top_categories"]), session["user_id"]),
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"result": result})


@ai_bp.route("/history", methods=["GET"])
@login_required
def analysis_history():
    try:
        limit = min(max(int(request.args.get("limit", 15)), 1), 100)
    except ValueError:
        return error_response("limit must be an integer.")

    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT l.*, u.username as analyzed_by_username
               FROM analysis_logs l LEFT JOIN users u ON l.analyzed_by = u.id
               ORDER BY l.analyzed_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    finally:
        conn.close()

    return jsonify({"history": rows_to_list(rows)})

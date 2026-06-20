"""
auth_routes.py
---------------
Handles account registration and session-based login/logout.

Auth strategy: Flask's built-in signed-cookie session. When a user logs
in successfully we store their id/username/role in `session`, which
Flask signs with SECRET_KEY and sends back as an HTTP-only cookie.
Because the frontend is served by this SAME Flask app (same origin),
the browser automatically attaches that cookie on every subsequent
fetch() call - no separate token handling needed on the frontend.
"""

import re
from flask import Blueprint, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash

from database import get_db_connection, row_to_dict
from utils import login_required, error_response

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not email or not password:
        return error_response("Username, email and password are all required.")
    if not USERNAME_RE.match(username):
        return error_response("Username must be 3-32 characters: letters, numbers, '.' or '_' only.")
    if not EMAIL_RE.match(email):
        return error_response("Please provide a valid email address.")
    if len(password) < 6:
        return error_response("Password must be at least 6 characters long.")

    conn = get_db_connection()
    try:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
        ).fetchone()
        if existing:
            return error_response("A user with that username or email already exists.", 409)

        password_hash = generate_password_hash(password)
        conn.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'analyst')",
            (username, email, password_hash),
        )
        conn.commit()
        return jsonify({"message": "Account created successfully. You can now log in."}), 201
    finally:
        conn.close()


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return error_response("Username and password are required.")

    conn = get_db_connection()
    try:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    finally:
        conn.close()

    if not user or not check_password_hash(user["password_hash"], password):
        return error_response("Invalid username or password.", 401)

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session.permanent = True

    return jsonify({
        "message": "Login successful.",
        "user": {"id": user["id"], "username": user["username"],
                  "email": user["email"], "role": user["role"]},
    })


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully."})


@auth_bp.route("/me", methods=["GET"])
@login_required
def me():
    conn = get_db_connection()
    try:
        user = conn.execute(
            "SELECT id, username, email, role, created_at FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()
    finally:
        conn.close()

    if not user:
        session.clear()
        return error_response("Session is no longer valid. Please log in again.", 401)

    return jsonify({"user": row_to_dict(user)})

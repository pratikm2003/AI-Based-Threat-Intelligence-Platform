"""
utils.py
--------
Small shared helpers used across multiple route files:
 - login_required / admin_required decorators (session based auth)
 - a consistent JSON error response helper
"""

from functools import wraps
from flask import session, jsonify


def login_required(view_func):
    """Reject the request with 401 unless a user is logged in (session cookie)."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "Authentication required. Please log in."}), 401
        return view_func(*args, **kwargs)
    return wrapped


def admin_required(view_func):
    """Reject the request with 403 unless the logged-in user has the admin role."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "Authentication required. Please log in."}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "Admin privileges required for this action."}), 403
        return view_func(*args, **kwargs)
    return wrapped


def error_response(message, status_code=400):
    return jsonify({"error": message}), status_code


def current_user_id():
    return session.get("user_id")

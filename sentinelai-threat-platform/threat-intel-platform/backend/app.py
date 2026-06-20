"""
app.py
------
Main entry point for the SentinelAI backend.

Run this file from inside the `backend/` folder:

    python app.py

What happens on startup:
    1. The SQLite database file + tables are created if they don't exist.
    2. Default admin/analyst accounts and sample threat data are seeded
       (only if the database is empty - safe to restart any time).
    3. The two AI models (URL classifier + text classifier) are loaded
       from disk, or trained fresh on first run if no .pkl files exist.
    4. All API blueprints are registered under /api/...
    5. The frontend (HTML/CSS/JS) is served directly by Flask from the
       ../frontend folder, so the whole project runs as a single server
       on a single port - no separate frontend server, no CORS needed.
"""

import os
import sys
import time
from datetime import datetime

from flask import Flask, send_from_directory, jsonify

import config
from database import init_db, get_db_connection
import seed_data

from routes.auth_routes import auth_bp
from routes.threat_routes import threat_bp
from routes.ai_routes import ai_bp
from routes.dashboard_routes import dashboard_bp
from routes.report_routes import report_bp


def create_app():
    app = Flask(
        __name__,
        static_folder=config.FRONTEND_DIR,
        static_url_path="",
    )
    app.secret_key = config.SECRET_KEY

    # Session cookie lifetime (used together with session.permanent = True
    # set at login time in auth_routes.py)
    app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 8  # 8 hours

    # ---- Register API blueprints ----
    app.register_blueprint(auth_bp)
    app.register_blueprint(threat_bp)
    app.register_blueprint(ai_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(report_bp)

    # ---- Serve the frontend ----
    @app.route("/")
    def serve_index():
        return send_from_directory(config.FRONTEND_DIR, "index.html")

    @app.route("/<path:filename>")
    def serve_frontend_file(filename):
        """Serve any other frontend file (dashboard.html, css/style.css, js/api.js, ...).
        Falls back to index.html for unknown paths so the app behaves
        sensibly even if a stray URL is typed in directly.
        """
        full_path = os.path.join(config.FRONTEND_DIR, filename)
        if os.path.isfile(full_path):
            return send_from_directory(config.FRONTEND_DIR, filename)
        return send_from_directory(config.FRONTEND_DIR, "index.html")

    # ---- Health check endpoint ----
    # This is the single most important endpoint for verifying the project
    # is "running good or not": it checks the database connection AND
    # confirms both AI models are trained and loadable.
    @app.route("/api/health", methods=["GET"])
    def health_check():
        status = {
            "status": "ok",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "checks": {},
        }
        http_code = 200

        # 1. Database check
        try:
            conn = get_db_connection()
            user_count = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
            threat_count = conn.execute("SELECT COUNT(*) c FROM threats").fetchone()["c"]
            conn.close()
            status["checks"]["database"] = {
                "ok": True,
                "users": user_count,
                "threats": threat_count,
            }
        except Exception as e:
            status["checks"]["database"] = {"ok": False, "error": str(e)}
            status["status"] = "error"
            http_code = 503

        # 2. AI model files check
        url_model_path = os.path.join(config.AI_MODELS_DIR, "url_model.pkl")
        text_model_path = os.path.join(config.AI_MODELS_DIR, "text_model.pkl")
        status["checks"]["ai_models"] = {
            "url_classifier_trained": os.path.isfile(url_model_path),
            "text_classifier_trained": os.path.isfile(text_model_path),
        }
        if not (os.path.isfile(url_model_path) and os.path.isfile(text_model_path)):
            status["status"] = "warning"

        status["project"] = "SentinelAI - AI-based Threat Intelligence Platform"
        return jsonify(status), http_code

    return app


def _ensure_ai_models_ready():
    """Pre-warm both AI models at startup so the very first request from
    a user doesn't have to wait for training. If the .pkl files already
    exist they are simply loaded; otherwise they are trained right now
    (takes only a few seconds on a normal laptop).
    """
    from ai_engine.url_classifier import predict_url, MODEL_PATH as URL_MODEL_PATH
    from ai_engine.text_classifier import predict_text, MODEL_PATH as TEXT_MODEL_PATH

    print("[SentinelAI] Checking AI models...")
    t0 = time.time()
    if not os.path.isfile(URL_MODEL_PATH):
        print("[SentinelAI]   URL classifier not found - training now...")
    predict_url("https://example.com")  # triggers lazy load/train
    if not os.path.isfile(TEXT_MODEL_PATH):
        print("[SentinelAI]   Text classifier not found - training now...")
    predict_text("a sample security incident description for warmup")
    print(f"[SentinelAI] AI models ready in {time.time() - t0:.2f}s")


if __name__ == "__main__":
    # Make sure backend/ is on sys.path even if launched from elsewhere
    sys.path.insert(0, config.BASE_DIR)

    print("=" * 60)
    print(" SentinelAI - AI-based Threat Intelligence Platform")
    print("=" * 60)

    print("[SentinelAI] Initializing database...")
    init_db()

    print("[SentinelAI] Seeding default accounts and sample data (if needed)...")
    seed_data.run()

    _ensure_ai_models_ready()

    app = create_app()

    print("-" * 60)
    print(f"  Open your browser at:  http://localhost:{config.PORT}")
    print(f"  Admin login:           {config.DEFAULT_ADMIN_USERNAME} / {config.DEFAULT_ADMIN_PASSWORD}")
    print(f"  Analyst login:         {config.DEFAULT_ANALYST_USERNAME} / {config.DEFAULT_ANALYST_PASSWORD}")
    print(f"  Health check:          http://localhost:{config.PORT}/api/health")
    print("-" * 60)

    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG, use_reloader=False)

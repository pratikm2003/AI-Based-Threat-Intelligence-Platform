"""
config.py
---------
Central configuration for the SentinelAI backend.
Keeping all paths and settings in one place makes the project
easy to understand and easy to grade.
"""

import os

# Base directory = /backend
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Project root = one level above /backend
PROJECT_ROOT = os.path.dirname(BASE_DIR)

# Where the SQLite database file lives
DATABASE_DIR = os.path.join(BASE_DIR, "database")
DATABASE_PATH = os.path.join(DATABASE_DIR, "threat_intel.db")

# Where the frontend (HTML/CSS/JS) lives - Flask will serve it directly
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")

# Where trained AI models (.pkl files) are stored
AI_MODELS_DIR = os.path.join(BASE_DIR, "ai_engine", "trained_models")

# Flask secret key - used to sign session cookies.
# In a real production system this would come from an environment
# variable. For a college project, a fixed value is fine.
SECRET_KEY = os.environ.get("SENTINELAI_SECRET_KEY", "sentinelai-college-project-secret-key-2026")

# Default admin account created automatically on first run
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_EMAIL = "admin@sentinelai.local"
DEFAULT_ADMIN_PASSWORD = "Admin@123"

# Default analyst account (non-admin) created automatically on first run
DEFAULT_ANALYST_USERNAME = "analyst"
DEFAULT_ANALYST_EMAIL = "analyst@sentinelai.local"
DEFAULT_ANALYST_PASSWORD = "Analyst@123"

# Allowed values for dropdowns / validation (kept in sync with frontend)
IOC_TYPES = ["ip", "domain", "url", "hash", "email"]
THREAT_TYPES = ["malware", "phishing", "ransomware", "ddos", "sql_injection",
                "botnet", "insider_threat", "network_intrusion", "other"]
SEVERITIES = ["low", "medium", "high", "critical"]
STATUSES = ["active", "investigating", "resolved"]

HOST = "0.0.0.0"
PORT = 5000
DEBUG = True

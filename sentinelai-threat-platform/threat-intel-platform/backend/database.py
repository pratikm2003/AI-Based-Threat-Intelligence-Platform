"""
database.py
------------
All raw SQLite access for the project lives here. We deliberately use
Python's built-in `sqlite3` module (no ORM) so the project has zero
extra database dependencies to install - just standard Python.

Tables:
    users           -> registered accounts (admin / analyst roles)
    threats         -> the threat intelligence records (IOCs)
    analysis_logs   -> history of every AI analysis that was run
"""

import sqlite3
import os
import config


def get_db_connection():
    """Return a new SQLite connection with rows accessible by column name."""
    os.makedirs(config.DATABASE_DIR, exist_ok=True)
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'analyst',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS threats (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_value        TEXT NOT NULL,
    ioc_type         TEXT NOT NULL,
    threat_type      TEXT NOT NULL,
    severity         TEXT NOT NULL,
    confidence_score INTEGER NOT NULL DEFAULT 50,
    status           TEXT NOT NULL DEFAULT 'active',
    description      TEXT,
    source           TEXT,
    detected_at      TEXT NOT NULL DEFAULT (datetime('now')),
    created_by       INTEGER,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS analysis_logs (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    input_type             TEXT NOT NULL,
    input_value            TEXT NOT NULL,
    prediction             TEXT NOT NULL,
    confidence             REAL NOT NULL,
    risk_factors           TEXT,
    matched_existing_threat INTEGER NOT NULL DEFAULT 0,
    analyzed_by            INTEGER,
    analyzed_at            TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (analyzed_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(threat_type);
CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);
CREATE INDEX IF NOT EXISTS idx_threats_detected_at ON threats(detected_at);
CREATE INDEX IF NOT EXISTS idx_logs_analyzed_at ON analysis_logs(analyzed_at);
"""


def init_db():
    """Create all tables (if they do not already exist)."""
    conn = get_db_connection()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def row_to_dict(row):
    """Convert a sqlite3.Row (or None) into a plain dict."""
    if row is None:
        return None
    return dict(row)


def rows_to_list(rows):
    return [dict(r) for r in rows]

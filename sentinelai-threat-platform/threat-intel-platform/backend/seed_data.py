"""
seed_data.py
-------------
Populates the database with:
  1. Two default accounts (admin + analyst) so the project can be
     logged into immediately without registering first.
  2. ~30 realistic sample threat intelligence records spread across
     the last 30 days, covering every severity / threat type / status,
     so the dashboard charts and reports look meaningful on first run.

Both steps are idempotent - they only insert data if the relevant
table is currently empty, so re-running app.py never creates duplicates.
"""

import random
from datetime import datetime, timedelta

from werkzeug.security import generate_password_hash

import config
from database import get_db_connection


def _seed_users(conn):
    count = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    if count > 0:
        return False

    conn.execute(
        "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
        (
            config.DEFAULT_ADMIN_USERNAME,
            config.DEFAULT_ADMIN_EMAIL,
            generate_password_hash(config.DEFAULT_ADMIN_PASSWORD),
        ),
    )
    conn.execute(
        "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'analyst')",
        (
            config.DEFAULT_ANALYST_USERNAME,
            config.DEFAULT_ANALYST_EMAIL,
            generate_password_hash(config.DEFAULT_ANALYST_PASSWORD),
        ),
    )
    conn.commit()
    return True


# Each entry: (ioc_value, ioc_type, threat_type, severity, source)
SAMPLE_THREATS = [
    ("185.220.101.47", "ip", "botnet", "critical", "AbuseIPDB"),
    ("45.155.205.233", "ip", "ddos", "high", "AbuseIPDB"),
    ("paypal-secure-verification.tk", "domain", "phishing", "critical", "PhishTank"),
    ("apple-id-confirm-account.xyz", "domain", "phishing", "high", "PhishTank"),
    ("bankofamerica-alert-secure.com", "domain", "phishing", "critical", "OpenPhish"),
    ("update-flash-player-now.top", "domain", "malware", "high", "VirusTotal"),
    ("http://192.168.77.4/login.php?id=1", "url", "phishing", "high", "Internal SOC"),
    ("http://secure-microsoft365-login.click/auth", "url", "phishing", "critical", "OpenPhish"),
    ("http://bit.ly/3xQrK9z", "url", "malware", "medium", "Internal SOC"),
    ("d41d8cd98f00b204e9800998ecf8427e", "hash", "malware", "medium", "VirusTotal"),
    ("44d88612fea8a8f36de82e1278abb02f", "hash", "ransomware", "critical", "VirusTotal"),
    ("e99a18c428cb38d5f260853678922e03", "hash", "ransomware", "critical", "Malware Bazaar"),
    ("c99a18c428cb38d5f260853678922e99", "hash", "malware", "high", "Malware Bazaar"),
    ("attacker-c2@protonmail.com", "email", "phishing", "medium", "Internal SOC"),
    ("hr-payroll-update@corp-mailer.net", "email", "phishing", "high", "Internal SOC"),
    ("103.45.67.12", "ip", "network_intrusion", "high", "Internal SOC"),
    ("198.51.100.23", "ip", "ddos", "medium", "AbuseIPDB"),
    ("91.219.236.18", "ip", "botnet", "high", "AbuseIPDB"),
    ("free-gift-card-claim-now.xyz", "domain", "phishing", "low", "PhishTank"),
    ("login-secure-icloud-verify.info", "domain", "phishing", "high", "OpenPhish"),
    ("torrent-crack-keygen-download.ru", "domain", "malware", "medium", "VirusTotal"),
    ("http://10.0.0.5:8080/admin", "url", "network_intrusion", "medium", "Internal SOC"),
    ("http://account-update-secure.tk/wp-login", "url", "phishing", "medium", "PhishTank"),
    ("9b74c9897bac770ffc029102a200c5de", "hash", "malware", "low", "VirusTotal"),
    ("internal-finance-share@dropbox-files.net", "email", "insider_threat", "medium", "Internal SOC"),
    ("203.0.113.55", "ip", "sql_injection", "medium", "Internal SOC"),
    ("legacy-app-test-server.local", "domain", "other", "low", "Internal SOC"),
    ("http://promo-discount-store.shop/checkout", "url", "other", "low", "Internal SOC"),
    ("172.16.254.1", "ip", "network_intrusion", "low", "Internal SOC"),
    ("hr-bonus-claim-form.xyz", "domain", "phishing", "medium", "OpenPhish"),
]

DESCRIPTIONS = {
    "phishing": "Phishing campaign impersonating a trusted brand to harvest user credentials.",
    "malware": "Indicator associated with malware distribution observed in recent telemetry.",
    "ransomware": "File hash linked to a known ransomware family encrypting victim files for ransom.",
    "ddos": "Source involved in distributed denial-of-service traffic flooding observed on the network.",
    "botnet": "Node identified as part of a botnet command-and-control infrastructure.",
    "sql_injection": "Repeated SQL injection attempts detected against a public-facing login form.",
    "insider_threat": "Unusual internal data access pattern flagged for review as potential insider activity.",
    "network_intrusion": "Unauthorized access attempt detected against internal network infrastructure.",
    "other": "Indicator flagged during routine monitoring for further analyst review.",
}

STATUSES_WEIGHTED = ["active", "active", "investigating", "investigating", "resolved"]


def _seed_threats(conn, admin_id, analyst_id):
    count = conn.execute("SELECT COUNT(*) c FROM threats").fetchone()["c"]
    if count > 0:
        return False

    rng = random.Random(7)  # fixed seed -> reproducible demo data
    now = datetime.utcnow()

    for i, (ioc_value, ioc_type, threat_type, severity, source) in enumerate(SAMPLE_THREATS):
        days_ago = rng.randint(0, 29)
        hours_ago = rng.randint(0, 23)
        detected_at = (now - timedelta(days=days_ago, hours=hours_ago)).strftime("%Y-%m-%d %H:%M:%S")

        confidence = {
            "critical": rng.randint(85, 99),
            "high": rng.randint(70, 90),
            "medium": rng.randint(45, 75),
            "low": rng.randint(20, 50),
        }[severity]

        status = rng.choice(STATUSES_WEIGHTED)
        created_by = admin_id if i % 3 == 0 else analyst_id
        description = DESCRIPTIONS.get(threat_type, "Indicator flagged for analyst review.")

        conn.execute(
            """INSERT INTO threats
               (ioc_value, ioc_type, threat_type, severity, confidence_score,
                status, description, source, detected_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ioc_value, ioc_type, threat_type, severity, confidence,
             status, description, source, detected_at, created_by),
        )

    conn.commit()
    return True


def run():
    conn = get_db_connection()
    try:
        users_seeded = _seed_users(conn)

        admin_row = conn.execute(
            "SELECT id FROM users WHERE username = ?", (config.DEFAULT_ADMIN_USERNAME,)
        ).fetchone()
        analyst_row = conn.execute(
            "SELECT id FROM users WHERE username = ?", (config.DEFAULT_ANALYST_USERNAME,)
        ).fetchone()
        admin_id = admin_row["id"] if admin_row else None
        analyst_id = analyst_row["id"] if analyst_row else admin_id

        threats_seeded = _seed_threats(conn, admin_id, analyst_id)

        if users_seeded:
            print("[SentinelAI]   Created default admin + analyst accounts.")
        else:
            print("[SentinelAI]   Users already exist - skipped account seeding.")

        if threats_seeded:
            print(f"[SentinelAI]   Inserted {len(SAMPLE_THREATS)} sample threat records.")
        else:
            print("[SentinelAI]   Threat records already exist - skipped sample data seeding.")
    finally:
        conn.close()


if __name__ == "__main__":
    from database import init_db
    init_db()
    run()

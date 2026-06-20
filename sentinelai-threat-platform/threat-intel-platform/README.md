# SentinelAI — AI-Based Threat Intelligence Platform

A full-stack web application for tracking security threats (Indicators of
Compromise) and using trained machine learning models to triage suspicious
URLs and incident reports. Built as a college project with a real SQLite
database, two genuinely trained scikit-learn models, and a from-scratch
HTML/CSS/JS frontend.

## Features

- **Authentication** — register/login/logout with hashed passwords and
  server-side sessions. Two roles: `admin` and `analyst`.
- **Threat database** — add, search, filter, paginate, update, and delete
  IOC records (IPs, domains, URLs, file hashes, emails). Deleting is
  restricted to admins (enforced both in the UI and the API).
- **AI URL Analyzer** — paste a URL/domain/IP and get an instant verdict
  (benign / suspicious / malicious) from a trained Random Forest model,
  along with plain-English risk factors and the underlying features.
  Known IOCs already in the database are matched directly before the
  model is even called.
- **AI Incident Text Classifier** — describe a security incident in plain
  language and a trained TF-IDF + Logistic Regression model predicts the
  most likely category (phishing, malware, ransomware, DDoS, SQL
  injection, insider threat, network intrusion), with a full probability
  breakdown.
- **Dashboard** — live stat cards, a 14-day detection trend chart, a
  severity breakdown donut chart, threat type distribution, and a recent
  threats table.
- **Reports** — date-range filtered summaries (7/30/90 days or all time)
  with charts and a one-click CSV export.
- **Health check endpoint** — `/api/health` reports database connectivity
  and whether both AI models are trained and loaded, so you can verify the
  whole stack is working with a single request.

## Tech stack

| Layer    | Technology |
|----------|------------|
| Backend  | Python, Flask, raw `sqlite3` (no ORM) |
| AI/ML    | scikit-learn (RandomForestClassifier, TF-IDF + LogisticRegression) |
| Frontend | Vanilla HTML, CSS, JavaScript (no framework, no build step) |
| Charts   | Chart.js (loaded from CDN) |
| Auth     | Flask signed-cookie sessions + Werkzeug password hashing |

No external services, API keys, or paid tools are required. Everything
runs locally with `pip install -r requirements.txt` and `python app.py`.

## Why no ORM / no CORS library?

The Flask app serves the frontend directly (same origin), so no CORS
configuration is needed. Raw `sqlite3` was used instead of an ORM to keep
the dependency list minimal and the SQL fully visible and explainable for
a college project / viva — every query in `routes/*.py` is plain,
readable SQL.

## Project structure

```
threat-intel-platform/
├── backend/
│   ├── app.py                  # Flask entry point — run this
│   ├── config.py                # Central configuration & constants
│   ├── database.py              # SQLite connection + schema
│   ├── seed_data.py             # Default accounts + sample data
│   ├── utils.py                 # Auth decorators, error helper
│   ├── requirements.txt
│   ├── ai_engine/
│   │   ├── feature_extraction.py   # URL → 16 engineered features
│   │   ├── url_classifier.py       # Random Forest URL model + training
│   │   ├── text_classifier.py      # TF-IDF + LogisticRegression text model
│   │   ├── train_models.py         # Standalone retrain script
│   │   ├── datasets/                # Exported CSV training datasets
│   │   └── trained_models/          # Saved .pkl model files
│   └── routes/
│       ├── auth_routes.py
│       ├── threat_routes.py
│       ├── ai_routes.py
│       ├── dashboard_routes.py
│       └── report_routes.py
└── frontend/
    ├── index.html / register.html       # Auth pages
    ├── dashboard.html / threats.html
    ├── analyzer.html / reports.html
    ├── css/style.css
    └── js/ (api.js, nav.js, auth.js, dashboard.js, threats.js,
            analyzer.js, reports.js)
```

See **HOW_TO_RUN.md** to get it running, and **TESTING_GUIDE.md** to
verify it's working correctly.

## About the AI models and their accuracy

Both models are trained on **real, exported CSV datasets** that ship in
this project (`backend/ai_engine/datasets/`) — not just numbers generated
in memory:

- **URL classifier**: 2,400 labeled URLs (`url_dataset.csv`), trained on
  16 engineered lexical features (HTTPS usage, entropy, suspicious
  keywords, IP-as-host, etc.) with a Random Forest. It scores **100%** on
  its held-out test split — expected and explainable, because the
  dataset is synthetically generated from clean, separable rules (similar
  in spirit to the classic UCI Phishing Websites dataset). This is an
  honest number for a rule-based synthetic dataset, not a real-world
  accuracy claim; a production system would retrain this same pipeline on
  a labeled feed such as PhishTank or OpenPhish.
- **Text classifier**: 1,181 labeled incident descriptions
  (`text_incidents_dataset.csv`), combining hand-written analyst notes
  with a template-based generator across 7 categories. Because the goal
  here was genuine accuracy rather than an inflated number, the model is
  evaluated three different ways and **all three are reported together**
  rather than cherry-picking the best one:
  - 5-fold cross-validation on the training corpus: **~99%** (expected to
    run high — near-duplicate generated sentences can land in both the
    train and validation fold).
  - A held-out set written in **everyday phrasing** a real analyzer user
    would type: **~96%** — this is the number shown as the model's
    reported accuracy in the app, since it's the most relevant to actual
    use.
  - A second, deliberately indirect "hard" held-out set (symptom-only
    descriptions with no category name anywhere in the sentence): **~66%**
    — kept and reported as an honest stress test of the model's limits,
    not hidden.

If you see a model claiming literal 100% on natural language in any
project, be skeptical — it almost always means overfitting, a duplicated
dataset, or test-set leakage. The numbers in this project are real and
reproducible by re-running `train_models.py`.

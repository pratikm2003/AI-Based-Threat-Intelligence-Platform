# How to Run SentinelAI

## Requirements

- Python 3.9 or newer
- pip

No internet connection is required to run the app itself (the only
internet-dependent piece is loading Google Fonts and Chart.js from a CDN
in the browser — the app still works without internet, just with system
fonts and no charts).

## Step 1 — Open a terminal in the project folder

```bash
cd threat-intel-platform/backend
```

All commands below are run from inside the `backend/` folder.

## Step 2 — (Recommended) Create a virtual environment

```bash
python3 -m venv venv

# macOS / Linux
source venv/bin/activate

# Windows (PowerShell)
venv\Scripts\Activate.ps1
```

## Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

This installs exactly four packages: Flask, scikit-learn, numpy, and
joblib.

## Step 4 — Run the app

```bash
python app.py
```

On first run you'll see output like this:

```
============================================================
 SentinelAI - AI-based Threat Intelligence Platform
============================================================
[SentinelAI] Initializing database...
[SentinelAI] Seeding default accounts and sample data (if needed)...
[SentinelAI]   Created default admin + analyst accounts.
[SentinelAI]   Inserted 30 sample threat records.
[SentinelAI] Checking AI models...
[SentinelAI] AI models ready in 0.0Xs
------------------------------------------------------------
  Open your browser at:  http://localhost:5000
  Admin login:           admin / Admin@123
  Analyst login:         analyst / Analyst@123
  Health check:          http://localhost:5000/api/health
------------------------------------------------------------
```

The very first run automatically:
1. Creates the SQLite database file and tables.
2. Seeds a default admin account and a default analyst account.
3. Seeds ~30 sample threat records so the dashboard isn't empty.
4. Trains both AI models if their `.pkl` files aren't already present
   (they're shipped pre-trained in this zip, so this should be instant —
   but it will retrain automatically if you delete them).

Every later run is much faster since the database and models already
exist — it just reuses them.

## Step 5 — Open the app

Go to **http://localhost:5000** in your browser.

Log in with one of the demo accounts (also clickable on the login page):

| Role    | Username | Password    |
|---------|----------|-------------|
| Admin   | admin    | Admin@123   |
| Analyst | analyst  | Analyst@123 |

Or click "Create one" to register your own account (new accounts default
to the `analyst` role).

## Stopping the server

Press `Ctrl + C` in the terminal where `app.py` is running.

## Resetting the data

To start completely fresh (new database, freshly seeded data, freshly
retrained models), stop the server and delete these, then run
`python app.py` again:

```bash
rm backend/database/threat_intel.db
rm backend/ai_engine/trained_models/*.pkl
```

(On Windows, delete those files via File Explorer or `del` instead of
`rm`.)

## Retraining the AI models manually

If you ever want to retrain both models from scratch on demand (for
example after editing the training data in `ai_engine/`):

```bash
cd backend
python ai_engine/train_models.py
```

This regenerates both `.pkl` files in `ai_engine/trained_models/` and
re-exports the labeled CSV datasets in `ai_engine/datasets/`.

## Common issues

**"Address already in use" / port 5000 busy** — another process is using
port 5000. Either stop it, or change `PORT` in `backend/config.py` and
restart.

**`ModuleNotFoundError`** — make sure you activated the virtual
environment (Step 2) and ran `pip install -r requirements.txt` (Step 3)
from inside the `backend/` folder.

**Browser shows a blank/broken page** — make sure you're visiting
`http://localhost:5000` (the Flask server itself), not opening
`frontend/index.html` directly as a `file://` URL — the frontend depends
on the backend serving it and the `/api/...` routes being on the same
origin.

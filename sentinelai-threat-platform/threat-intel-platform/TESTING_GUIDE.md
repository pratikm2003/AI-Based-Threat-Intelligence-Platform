# Testing & Verification Guide

This guide shows you how to confirm the whole platform — database, AI
models, backend API, and frontend — is genuinely working, not just that
the server started.

## 1. The single fastest check: the health endpoint

With the app running, visit (or `curl`):

```
http://localhost:5000/api/health
```

A healthy response looks like:

```json
{
  "status": "ok",
  "checks": {
    "database": { "ok": true, "users": 2, "threats": 30 },
    "ai_models": { "url_classifier_trained": true, "text_classifier_trained": true }
  },
  "project": "SentinelAI - AI-based Threat Intelligence Platform",
  "timestamp": "..."
}
```

- `status: "ok"` → everything is healthy.
- `status: "warning"` → database is fine but one or both AI models
  haven't been trained yet (rare — they auto-train on first run).
- `status: "error"` with HTTP 503 → the database itself failed; check the
  terminal running `app.py` for the error.

## 2. Log in and look around

1. Go to `http://localhost:5000`.
2. Click the **Admin** demo-account button (autofills credentials), then
   **Sign in**.
3. You should land on the **Dashboard** with:
   - Four stat cards showing real numbers (not zeros, since sample data
     is seeded on first run).
   - A 14-day trend line chart and a severity donut chart, both populated.
   - A "Recent threats" table with real rows.

If any of this is blank, open the browser console (F12) and check for
errors — and check the terminal running `app.py` for a stack trace.

## 3. Test the Threats page

1. Click **Threats** in the sidebar.
2. Try the search box and the severity/type/status filters — the table
   should update.
3. Click **Add threat**, fill in an IOC value (e.g. `test-domain.tk`),
   and submit. It should appear in the table immediately.
4. Change a threat's status using the dropdown in its row — it should
   save silently (a toast confirms it).
5. If logged in as **admin**, you'll see a delete (trash) icon on each
   row — try deleting the test threat you just added. If logged in as
   **analyst**, that icon is hidden (the backend also blocks the delete
   API call directly for non-admins, so this is enforced server-side too,
   not just hidden in the UI).

## 4. Test the AI URL Analyzer

Go to **AI Analyzer** → **URL Analyzer** tab.

Try a clearly malicious-looking pattern:

```
http://192.168.5.9/secure/login.php?verify=account
```

Expected: a red **Malicious** banner, a high confidence percentage, and a
list of risk factors (e.g. "Uses a raw IP address...", "Contains N
security-sensitive keywords...").

Then try a known-good URL:

```
https://github.com/torvalds/linux
```

Expected: a green **Benign** banner with low/zero malicious probability.

Then try an IOC that's already in the seeded sample data, e.g.:

```
185.220.101.47
```

Expected: the result banner should say it matched the **threat
database** directly (not the AI model) — this demonstrates the platform
checks known threats before falling back to the ML model.

## 5. Test the AI Incident Text Classifier

Go to the **Incident Text Classifier** tab and try:

```
All files on the shared drive were suddenly encrypted and a note
demanded bitcoin payment to unlock them.
```

Expected: predicted category **ransomware** (or a closely related
category) with a confidence percentage and a category probability
breakdown below it.

Try a few more in your own words — phishing, DDoS, SQL injection, etc. —
and see if the predictions look reasonable. The model's realistic-usage
accuracy is documented in `README.md`.

## 6. Test Reports + CSV export

1. Go to **Reports**.
2. Switch between the 7d / 30d / 90d / All time range pills — the stat
   cards, charts, and breakdown table should all update.
3. Click **Export CSV** — a file named like
   `sentinelai_threat_report_30d.csv` should download. Open it in any
   spreadsheet program to confirm the rows match what's shown on screen.

## 7. Test logout + session protection

1. Click the logout icon in the sidebar.
2. You should be redirected to the login page.
3. Try visiting `http://localhost:5000/dashboard.html` directly while
   logged out — you should be bounced back to the login page (this is
   the frontend's auth guard calling `/api/auth/me` and redirecting on a
   401).

## 8. Re-verify the AI models' honesty (optional, for the viva)

From `backend/`, run:

```bash
python ai_engine/train_models.py
```

This reprints the same accuracy numbers documented in `README.md` —
useful if an instructor asks "how do you know the model actually
works?" You can show the printed cross-validation scores, the realistic
held-out accuracy, and the deliberately harder held-out accuracy, all
computed live in front of them, plus the exported CSV datasets in
`backend/ai_engine/datasets/` that back the numbers.

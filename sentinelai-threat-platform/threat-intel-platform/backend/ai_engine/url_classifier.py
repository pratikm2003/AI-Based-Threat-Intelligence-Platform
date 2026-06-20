"""
url_classifier.py
-------------------
A real, working scikit-learn model that scores a URL/domain/IP as
malicious or benign, based on the lexical features in
feature_extraction.py.

IMPORTANT (for the project report / viva):
This model is trained on a SYNTHETIC, RULE-GENERATED dataset created
by generate_training_dataset() below, because the project must run
fully offline with no external downloads. The generation functions
encode well known phishing/malicious-URL patterns (raw IPs, suspicious
keywords, excessive subdomains/hyphens, high entropy domains, URL
shorteners, etc.) which are the same signals used in real published
research such as the UCI "Phishing Websites" dataset. For production
use, you would retrain on a real labeled feed such as PhishTank,
OpenPhish, or a SIEM's historical IOC database - the code below would
not need to change, only the data source.
"""

import os
import random
import string

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

import config
from ai_engine.feature_extraction import (
    extract_url_features,
    features_to_vector,
    build_risk_factors,
    SUSPICIOUS_WORDS,
    FEATURE_ORDER,
)

MODEL_PATH = os.path.join(config.AI_MODELS_DIR, "url_model.pkl")

BENIGN_DOMAINS = [
    "google.com", "wikipedia.org", "github.com", "example.com", "openlibrary.org",
    "python.org", "stackoverflow.com", "nytimes.com", "bbc.com", "coursera.org",
    "khanacademy.org", "mozilla.org", "apple.com", "microsoft.com", "amazon.com",
    "nationalgeographic.com", "spotify.com", "reddit.com", "yahoo.com", "linkedin.com",
    "harvard.edu", "mit.edu", "who.int", "un.org", "nasa.gov",
]
BENIGN_PATHS = [
    "/", "/about", "/contact", "/products/item-42", "/blog/post-1",
    "/search?q=python+tutorial", "/docs/help", "/user/profile", "/news/today",
    "/articles/2026/06/report", "/category/technology", "/", "/careers",
    "/support/faq", "/pricing",
]
BENIGN_SUBDOMAINS = ["", "www.", "mail.", "shop.", "news.", "support.", "docs."]

FAKE_TLDS = ["tk", "xyz", "top", "info", "click", "buzz", "win", "loan"]


def _random_str(n, charset=string.ascii_lowercase + string.digits):
    return "".join(random.choices(charset, k=n))


def gen_benign_url():
    domain = random.choice(BENIGN_DOMAINS)
    sub = random.choice(BENIGN_SUBDOMAINS)
    path = random.choice(BENIGN_PATHS)
    return f"https://{sub}{domain}{path}"


def gen_malicious_url():
    pattern = random.choice([
        "ip_address", "suspicious_keyword", "many_hyphens", "fake_tld_random",
        "at_symbol", "long_query", "high_entropy_subdomain", "non_https_login",
    ])

    if pattern == "ip_address":
        ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
        page = random.choice(["login.php", "verify.php", "update-account.html", "secure/index.php"])
        return f"http://{ip}/{page}"

    if pattern == "suspicious_keyword":
        word = random.choice(SUSPICIOUS_WORDS)
        domain = f"{word}-{_random_str(6)}.{random.choice(FAKE_TLDS)}"
        return f"http://{domain}/{word}/confirm-now"

    if pattern == "many_hyphens":
        brand = random.choice(["paypal", "bankofamerica", "appleid", "netflix", "microsoft"])
        domain = f"{brand}-account-{_random_str(4)}-secure-{_random_str(3)}.{random.choice(FAKE_TLDS)}"
        return f"http://{domain}/login"

    if pattern == "fake_tld_random":
        domain = f"{_random_str(10)}.{random.choice(FAKE_TLDS)}"
        return f"http://{domain}/"

    if pattern == "at_symbol":
        brand = random.choice(["paypal.com", "google.com", "apple.com"])
        return f"http://{brand}@{_random_str(8)}.{random.choice(FAKE_TLDS)}/secure"

    if pattern == "long_query":
        domain = f"{_random_str(9)}.{random.choice(FAKE_TLDS)}"
        params = "&".join(f"{_random_str(4)}={_random_str(8)}" for _ in range(6))
        return f"http://{domain}/redirect?{params}"

    if pattern == "high_entropy_subdomain":
        sub = _random_str(14, charset=string.ascii_lowercase + string.digits)
        domain = random.choice(["secure-login", "account-verify", "service-update"])
        return f"http://{sub}.{domain}.{random.choice(FAKE_TLDS)}/"

    if pattern == "non_https_login":
        word = random.choice(["login", "verify", "secure", "signin"])
        domain = f"{word}-{_random_str(5)}-{_random_str(5)}.{random.choice(FAKE_TLDS)}"
        return f"http://{domain}/{word}.html?session={_random_str(10)}"

    return f"http://{_random_str(10)}.{random.choice(FAKE_TLDS)}/"


def generate_raw_dataset(n_per_class=1200, seed=42):
    """Generate the raw (url_string, label) pairs behind the dataset.
    label: 1 = malicious, 0 = benign.
    Kept separate from generate_training_dataset() so the exact same
    rows can be exported to a CSV file for grading/transparency via
    export_dataset_csv() below - the CSV *is* what the model is trained on.
    """
    random.seed(seed)
    rows = []
    for _ in range(n_per_class):
        rows.append((gen_benign_url(), 0))
    for _ in range(n_per_class):
        rows.append((gen_malicious_url(), 1))
    random.shuffle(rows)
    return rows


def generate_training_dataset(n_per_class=1200, seed=42):
    """Build a balanced synthetic dataset of (features, label) pairs.
    label: 1 = malicious, 0 = benign
    """
    rows = generate_raw_dataset(n_per_class, seed)
    X, y = [], []
    for url, label in rows:
        feats, _ = extract_url_features(url)
        X.append(features_to_vector(feats))
        y.append(label)
    return np.array(X, dtype=float), np.array(y, dtype=int)


def export_dataset_csv(path=None, n_per_class=1200, seed=42):
    """Write the full labeled URL dataset (raw input + every engineered
    feature + label) to a CSV file so it exists as a real, inspectable
    dataset artifact alongside the trained model - not just numbers
    generated in memory at train time.
    """
    import csv
    if path is None:
        path = os.path.join(config.AI_MODELS_DIR, "..", "datasets", "url_dataset.csv")
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    rows = generate_raw_dataset(n_per_class, seed)
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"] + FEATURE_ORDER)
        for url, label in rows:
            feats, _ = extract_url_features(url)
            writer.writerow(
                [url, "malicious" if label == 1 else "benign"]
                + [feats[k] for k in FEATURE_ORDER]
            )
    return path, len(rows)


def train_url_model(save=True, verbose=True):
    X, y = generate_training_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=160,
        max_depth=12,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    train_acc = accuracy_score(y_train, model.predict(X_train))
    test_acc = accuracy_score(y_test, model.predict(X_test))

    if verbose:
        print(f"[url_classifier] train accuracy: {train_acc:.4f}  |  test accuracy: {test_acc:.4f}")
        importances = sorted(
            zip(FEATURE_ORDER, model.feature_importances_),
            key=lambda t: t[1], reverse=True,
        )
        print("[url_classifier] top features:", [f"{n}({v:.2f})" for n, v in importances[:5]])

    if save:
        os.makedirs(config.AI_MODELS_DIR, exist_ok=True)
        joblib.dump(
            {"model": model, "feature_order": FEATURE_ORDER, "test_accuracy": test_acc},
            MODEL_PATH,
        )
        csv_path, n_rows = export_dataset_csv()
        if verbose:
            print(f"[url_classifier] dataset exported: {csv_path} ({n_rows} rows)")
    return model, test_acc


_loaded = None  # in-memory cache so we don't hit disk on every request


def _load_model():
    global _loaded
    if _loaded is None:
        if not os.path.exists(MODEL_PATH):
            train_url_model()
        _loaded = joblib.load(MODEL_PATH)
    return _loaded


def predict_url(raw_input):
    """
    Returns a structured dict describing the model's verdict on a single
    URL / domain / IP string, plus a human-readable explanation.
    """
    bundle = _load_model()
    model = bundle["model"]

    features, host = extract_url_features(raw_input)
    vector = np.array([features_to_vector(features)], dtype=float)

    proba = model.predict_proba(vector)[0]
    malicious_proba = float(proba[1])

    if malicious_proba >= 0.70:
        verdict = "malicious"
    elif malicious_proba >= 0.40:
        verdict = "suspicious"
    else:
        verdict = "benign"

    confidence = malicious_proba * 100 if verdict != "benign" else (1 - malicious_proba) * 100

    return {
        "input": raw_input,
        "host": host,
        "verdict": verdict,
        "malicious_probability": round(malicious_proba * 100, 2),
        "confidence": round(confidence, 2),
        "risk_factors": build_risk_factors(features, host),
        "features": features,
        "model_test_accuracy": round(bundle.get("test_accuracy", 0) * 100, 2),
    }


if __name__ == "__main__":
    train_url_model()

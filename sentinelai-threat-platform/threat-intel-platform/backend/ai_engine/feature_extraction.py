"""
feature_extraction.py
----------------------
Converts a raw URL / domain / IP string into a fixed-length numeric
feature vector that a machine learning model can understand.

This is the same general technique used in real published phishing /
malicious-URL detection research (e.g. the UCI "Phishing Websites"
dataset): instead of feeding raw text to the model, we engineer
lexical features that tend to differ between legitimate and malicious
links, then let a classifier learn the patterns.

FEATURE_ORDER defines the exact order features are turned into a
vector - the SAME order must be used at training time and at
prediction time, which is why it lives in one shared place.
"""

import math
import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "account", "update", "confirm", "signin",
    "bank", "paypal", "password", "billing", "suspend", "urgent", "click",
    "free", "win", "gift", "invoice", "wallet", "crypto", "reset", "unlock",
    "limited", "alert", "support",
]

SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]

# The order below is the contract between training and prediction.
FEATURE_ORDER = [
    "url_length",
    "host_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "num_subdomains",
    "has_ip",
    "has_at_symbol",
    "has_https",
    "num_special_chars",
    "num_query_params",
    "suspicious_word_count",
    "entropy",
    "has_port",
    "is_shortener",
]


def shannon_entropy(s):
    """Higher entropy = more 'random looking' string (typical of
    machine-generated malicious domains)."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_ip_address(host):
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    return bool(re.match(pattern, host or ""))


def normalize_input(raw):
    """Accept a bare domain/IP, a domain with a path, or a full URL and
    return something urlparse can work with consistently."""
    raw = (raw or "").strip()
    if not re.match(r"^[a-zA-Z]+://", raw):
        return "http://" + raw
    return raw


def extract_url_features(raw_input):
    """
    Returns (features_dict, parsed_host) for the given raw input string.
    """
    url = raw_input.strip()
    parse_target = normalize_input(url)
    parsed = urlparse(parse_target)
    netloc = parsed.netloc
    host = netloc.split("@")[-1].split(":")[0] if netloc else ""
    path = parsed.path or ""
    query = parsed.query or ""

    features = {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_subdomains": max(host.count(".") - 1, 0) if host else 0,
        "has_ip": 1 if is_ip_address(host) else 0,
        "has_at_symbol": 1 if "@" in url else 0,
        "has_https": 1 if url.lower().startswith("https://") else 0,
        "num_special_chars": sum(url.count(c) for c in ["%", "=", "&", "?", "_"]),
        "num_query_params": len(query.split("&")) if query else 0,
        "suspicious_word_count": sum(1 for w in SUSPICIOUS_WORDS if w in url.lower()),
        "entropy": round(shannon_entropy(host if host else url), 3),
        "has_port": 1 if (":" in netloc and not netloc.lower().startswith("www")) else 0,
        "is_shortener": 1 if any(s in host for s in SHORTENER_DOMAINS) else 0,
    }
    return features, host


def features_to_vector(features):
    """Turn the dict into a list in the fixed FEATURE_ORDER."""
    return [features[name] for name in FEATURE_ORDER]


def build_risk_factors(features, host):
    """
    Human-readable explanations of WHY a URL looks risky, derived from
    the same engineered features the model uses. This is what makes
    the tool 'explainable' rather than a black box probability.
    """
    factors = []

    if features["has_ip"]:
        factors.append("Uses a raw IP address instead of a domain name")
    if features["has_at_symbol"]:
        factors.append("Contains an '@' symbol, which can hide the real destination")
    if not features["has_https"]:
        factors.append("Does not use HTTPS encryption")
    if features["suspicious_word_count"] >= 2:
        factors.append(f"Contains {features['suspicious_word_count']} security-sensitive keywords (e.g. login, verify, secure)")
    elif features["suspicious_word_count"] == 1:
        factors.append("Contains a security-sensitive keyword (e.g. login, verify, secure)")
    if features["num_hyphens"] >= 4:
        factors.append(f"Unusually high number of hyphens in the URL ({features['num_hyphens']})")
    if features["num_subdomains"] >= 3:
        factors.append(f"Excessive number of subdomains ({features['num_subdomains']})")
    if features["url_length"] >= 75:
        factors.append(f"Unusually long URL ({features['url_length']} characters)")
    if features["entropy"] >= 3.8:
        factors.append(f"High character randomness in the domain (entropy {features['entropy']}), typical of generated malicious domains")
    if features["is_shortener"]:
        factors.append("Uses a URL shortening service, which can mask the true destination")
    if features["has_port"]:
        factors.append("Connects on a non-standard port")
    if features["num_digits"] >= 8:
        factors.append("Domain/path contains an unusually large number of digits")

    if not factors:
        factors.append("No major lexical risk indicators were found")
    return factors

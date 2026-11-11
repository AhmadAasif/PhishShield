from __future__ import annotations

import csv
import ipaddress
import math
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import joblib
from sklearn.ensemble import RandomForestClassifier

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "data" / "training_urls.csv"
MODEL_DIR = BASE_DIR / "model"
MODEL_PATH = MODEL_DIR / "phishshield_model.joblib"

FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length",
    "dot_count", "hyphen_count", "at_count", "question_count",
    "equal_count", "percent_count", "digit_count", "subdomain_count",
    "has_https", "has_ip", "has_port", "has_punycode",
    "has_suspicious_keyword", "has_shortener", "has_suspicious_tld",
    "has_double_slash_path", "brand_in_subdomain", "brand_mismatch",
    "encoded_chars", "domain_digit_ratio", "parameter_count",
    "host_entropy", "has_fragment"
]

SUSPICIOUS_WORDS = {
    "login", "signin", "verify", "verification", "secure", "account",
    "update", "confirm", "password", "banking", "wallet", "payment",
    "suspended", "unlock", "recover", "webscr", "bonus", "prize",
    "gift", "claim", "invoice", "auth", "support", "alert"
}
BRANDS = {
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "sbi", "icici", "hdfc", "axisbank",
    "onlinesbi", "flipkart", "whatsapp", "telegram"
}
SUSPICIOUS_TLDS = {
    "zip", "top", "xyz", "click", "work", "support", "country",
    "gq", "tk", "ml", "cf", "ga", "rest", "fit", "quest"
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rebrand.ly"
}
MULTI_PART_SUFFIXES = {
    "co.in", "com.au", "co.uk", "org.uk", "ac.in", "gov.in",
    "net.in", "com.br", "co.nz", "com.sg"
}


def normalize_url(raw_url: str) -> str:
    """Normalize a user-entered URL without visiting it."""
    value = (raw_url or "").strip()
    if not value:
        raise ValueError("Please enter a website URL.")
    if len(value) > 2048:
        raise ValueError("The URL is too long. Please enter a URL under 2,048 characters.")
    if any(ch.isspace() for ch in value):
        raise ValueError("The URL cannot contain spaces.")
    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        # Accessing .port validates malformed port values.
        _ = parsed.port
    except ValueError:
        raise ValueError("This URL appears to be malformed.")

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS website URLs can be checked.")
    if not hostname:
        raise ValueError("Please enter a valid website address, such as example.com.")

    return value


def _registered_domain(hostname: str) -> str:
    host = hostname.lower().strip(".")
    labels = [part for part in host.split(".") if part]
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_features(url: str) -> dict[str, float]:
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    host_labels = [part for part in hostname.split(".") if part]
    registered = _registered_domain(hostname)
    subdomain = ".".join(host_labels[:-len(registered.split("."))]) if registered else ""
    tld = host_labels[-1] if host_labels else ""

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    try:
        port = parsed.port
        has_port = int(port is not None and port not in {80, 443})
    except ValueError:
        has_port = 1

    lower_url = url.lower()
    searchable = lower_url
    has_keyword = int(any(word in searchable for word in SUSPICIOUS_WORDS))
    has_shortener = int(any(hostname == item or hostname.endswith("." + item) for item in SHORTENERS))
    has_suspicious_tld = int(tld in SUSPICIOUS_TLDS)
    brand_in_subdomain = int(any(brand in subdomain for brand in BRANDS))
    brand_mismatch = int(
        any(brand in hostname for brand in BRANDS)
        and not any(brand in registered for brand in BRANDS)
    )
    digit_count = sum(ch.isdigit() for ch in url)
    domain_digits = sum(ch.isdigit() for ch in hostname)

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "at_count": url.count("@"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "percent_count": url.count("%"),
        "digit_count": digit_count,
        "subdomain_count": max(0, len(host_labels) - len(registered.split("."))),
        "has_https": int(parsed.scheme.lower() == "https"),
        "has_ip": has_ip,
        "has_port": has_port,
        "has_punycode": int("xn--" in hostname),
        "has_suspicious_keyword": has_keyword,
        "has_shortener": has_shortener,
        "has_suspicious_tld": has_suspicious_tld,
        "has_double_slash_path": int("//" in path),
        "brand_in_subdomain": brand_in_subdomain,
        "brand_mismatch": brand_mismatch,
        "encoded_chars": int("%" in url),
        "domain_digit_ratio": domain_digits / max(1, len(hostname)),
        "parameter_count": len([part for part in query.split("&") if part]),
        "host_entropy": _entropy(hostname),
        "has_fragment": int(bool(parsed.fragment)),
    }
    return features


def _rule_analysis(url: str) -> tuple[int, list[str]]:
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower()
    path_query = ((parsed.path or "") + "?" + (parsed.query or "")).lower()
    features = extract_features(url)
    score = 0
    reasons = []

    def add(points: int, message: str):
        nonlocal score
        score += points
        reasons.append(message)

    if features["has_ip"]:
        add(25, "The website uses an IP address instead of a normal domain name.")
    if features["at_count"]:
        add(22, "The URL contains an @ symbol, which can hide the real destination.")
    if features["has_punycode"]:
        add(15, "The domain contains encoded characters that can imitate other names.")
    if features["brand_mismatch"]:
        add(22, "A well-known brand name appears in a different website's domain.")
    elif features["brand_in_subdomain"]:
        add(12, "A brand name appears in a subdomain rather than the main domain.")
    if features["has_suspicious_tld"]:
        add(10, "The domain uses a top-level domain often seen in suspicious link samples.")
    if features["has_shortener"]:
        add(8, "The link uses a URL-shortening service, so its final destination is hidden.")
    if features["has_suspicious_keyword"]:
        add(9, "The URL contains words commonly used in account-verification or payment lures.")
    if len(url) > 120:
        add(12, "The URL is unusually long.")
    elif len(url) > 75:
        add(6, "The URL is longer than many ordinary website addresses.")
    if features["subdomain_count"] >= 3:
        add(9, "The website has several nested subdomains.")
    if not features["has_https"]:
        add(5, "The link does not use HTTPS.")
    if features["has_port"]:
        add(7, "The URL specifies an unusual network port.")
    if features["hyphen_count"] >= 4:
        add(6, "The URL contains an unusually high number of hyphens.")
    if features["encoded_chars"]:
        add(4, "The URL contains percent-encoded characters.")
    if "//" in (parsed.path or ""):
        add(4, "The URL contains an extra double-slash sequence in its path.")

    return min(score, 100), reasons


class PhishingDetector:
    def __init__(self):
        self.model, self.sample_count = self._load_or_train()

    def _load_or_train(self):
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        if MODEL_PATH.exists():
            try:
                saved = joblib.load(MODEL_PATH)
                return saved["model"], saved.get("sample_count", 0)
            except Exception:
                # Rebuild a damaged or incompatible local model.
                pass

        if not DATASET_PATH.exists():
            raise RuntimeError("Training data is missing: data/training_urls.csv")

        urls, labels = [], []
        with DATASET_PATH.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                url = normalize_url(row["url"])
                urls.append([extract_features(url)[name] for name in FEATURE_NAMES])
                labels.append(int(row["label"]))

        if len(set(labels)) < 2 or len(urls) < 10:
            raise RuntimeError("The training CSV must contain at least 10 rows and both labels 0 and 1.")

        model = RandomForestClassifier(
            n_estimators=250,
            max_depth=12,
            min_samples_leaf=1,
            class_weight="balanced",
            random_state=42,
        )
        model.fit(urls, labels)
        joblib.dump({"model": model, "sample_count": len(urls)}, MODEL_PATH)
        return model, len(urls)

    def scan(self, raw_url: str) -> dict:
        url = normalize_url(raw_url)
        features = extract_features(url)
        feature_row = [[features[name] for name in FEATURE_NAMES]]
        probabilities = self.model.predict_proba(feature_row)[0]
        classes = list(self.model.classes_)
        phishing_probability = float(probabilities[classes.index(1)]) if 1 in classes else 0.0
        ml_score = round(phishing_probability * 100)

        rule_score, reasons = _rule_analysis(url)
        # Hybrid score: the trained model contributes 40%, transparent URL rules 60%.
        risk_score = round((0.40 * ml_score) + (0.60 * rule_score))
        risk_score = max(0, min(100, risk_score))

        if risk_score >= 60:
            verdict = "Likely Phishing"
            level = "high"
        elif risk_score >= 30:
            verdict = "Suspicious"
            level = "medium"
        else:
            verdict = "Low Risk"
            level = "low"

        if not reasons:
            reasons.append("No major URL red flags were detected by the built-in checks.")

        return {
            "url": url,
            "verdict": verdict,
            "level": level,
            "risk_score": risk_score,
            "ml_score": ml_score,
            "rule_score": rule_score,
            "reasons": reasons,
            "disclaimer": "This is an educational screening tool, not a guarantee. Do not enter passwords or payment details on a site just because it receives a low-risk result.",
        }


def train_model(force: bool = False) -> int:
    if force and MODEL_PATH.exists():
        MODEL_PATH.unlink()
    detector = PhishingDetector()
    return detector.sample_count

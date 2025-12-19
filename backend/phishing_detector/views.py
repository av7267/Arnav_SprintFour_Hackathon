from pathlib import Path
import joblib
from django.shortcuts import render
from datetime import datetime
import pandas as pd

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR.parent / "ml_model" / "phishing_model.pkl"

# Load ML model (numeric features)
model = joblib.load(MODEL_PATH)

# In-memory log of past scans
scan_logs = []

# Rule-based URL analysis for explanations
def analyze_url(url):
    reasons = []
    if "@" in url:
        reasons.append("Contains '@' symbol")
    if url.count(".") > 3:
        reasons.append("Too many subdomains")
    suspicious_tlds = [".xyz", ".top", ".ru", ".info"]
    if any(url.endswith(tld) for tld in suspicious_tlds):
        reasons.append("Suspicious domain extension")
    if len(url) > 75:
        reasons.append("URL is unusually long")
    return reasons[:3]  # top 3 reasons only

# Map probability to risk level
def get_risk_level(prob):
    if prob < 0.3:
        return "Low"
    elif prob < 0.6:
        return "Medium"
    else:
        return "High"

# Extract numeric features from URL
def extract_features_from_url(url):
    # Match exact column names used in training
    features = {
        "length_url": len(url),
        "nb_dots": url.count("."),
        "nb_hyphens": url.count("-"),
        "nb_at": url.count("@"),
        "nb_slash": url.count("/"),
        "nb_qm": url.count("?"),    # renamed to match model
        "nb_and": url.count("&"),
        "nb_percent": url.count("%"),
        "nb_eq": url.count("="),    # renamed to match model
    }
    return pd.DataFrame([features])

def detect_url(request):
    prediction = None
    prob = None
    risk = None
    reasons = []
    url = ""

    if request.method == "POST":
        url = request.POST.get("url", "")
        if url.strip():
            # Extract numeric features
            X_input = extract_features_from_url(url)

            # Predict using trained model
            pred = model.predict(X_input)[0]
            proba = model.predict_proba(X_input)[0].max()

            # Assign prediction label
            prediction = "Phishing / Suspicious" if pred == 1 else "Legitimate / Safe"

            # Confidence probability
            prob = round(float(proba) * 100, 2)
            risk = get_risk_level(proba)

            # Generate explanations
            reasons = analyze_url(url)

            # Log the scan
            scan_logs.insert(0, {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "url": url,
                "prediction": prediction,
                "prob": prob,
                "risk": risk,
                "reasons": reasons
            })
            # Keep only last 10 scans
            if len(scan_logs) > 10:
                scan_logs.pop()

    return render(request, "detect_url.html", {
        "prediction": prediction,
        "prob": prob,
        "risk": risk,
        "reasons": reasons,
        "url": url,
        "scan_logs": scan_logs,
    })
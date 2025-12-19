from pathlib import Path
import joblib
from django.shortcuts import render
from datetime import datetime
import pandas as pd
import re
import imaplib
import email

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
def get_risk_level(prob, pred):
    """
    prob: phishing probability (class=1)
    pred: model class (0 = legitimate, 1 = phishing)
    """

    if pred == 0:
        if prob < 0.25:
            return "Low"
        elif prob < 0.5:
            return "Medium"
        else:
            return "Medium"  # never High for legit

    # phishing class
    if prob >= 0.8:
        return "High"
    elif prob >= 0.45:
        return "Medium"
    else:
        return "Low"

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

def extract_urls_from_text(text):
    return re.findall(r'https?://[^\s]+', text)

def detect_url(request):
    prediction = None
    prob = None
    risk = None
    reasons = []
    url = ""
    email_text = ""

    if request.method == "POST":
        url = request.POST.get("url", "").strip()
        email_text = request.POST.get("email_text", "").strip()

        urls_to_scan = []

        if url:
            urls_to_scan.append(url)

        if email_text:
            extracted = extract_urls_from_text(email_text)
            urls_to_scan.extend(extracted)

        for u in urls_to_scan:
            X_input = extract_features_from_url(u)
            pred = model.predict(X_input)[0]
            proba = model.predict_proba(X_input)[0][1]

            prediction = "Phishing / Suspicious" if pred == 1 else "Legitimate / Safe"
            prob = round(float(proba) * 100, 2)
            risk = get_risk_level(proba, pred)
            reasons = analyze_url(u)

            # Heuristics should only nudge risk, not override model
            if reasons and pred == 1 and risk == "Low":
                risk = "Medium"

            scan_logs.insert(0, {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "url": u,
                "prediction": prediction,
                "prob": prob,
                "risk": risk,
                "reasons": reasons
            })

        if len(scan_logs) > 10:
            del scan_logs[10:]

    return render(request, "detect_url.html", {
        "url": url,
        "email_text": email_text,
        "scan_logs": scan_logs,
    })


# ------------------ IMAP Inbox Scanning ------------------

def scan_inbox(request):
    results = []
    error = None

    if request.method == "POST":
        imap_server = request.POST.get("imap_server", "imap.gmail.com")
        email_account = request.POST.get("email_account", "").strip()
        app_password = request.POST.get("app_password", "").strip()
        num_emails = int(request.POST.get("num_emails", 10))

        # Connect to IMAP
        if not email_account or not app_password:
            error = "Email and app password are required."
        else:
            try:
                mail = imaplib.IMAP4_SSL(imap_server)
                mail.login(email_account, app_password)
                mail.select("inbox")
                
                # Fetch last N emails
                status, messages = mail.search(None, "ALL")
                email_ids = messages[0].split()[-num_emails:]

                for eid in reversed(email_ids):
                    _, msg_data = mail.fetch(eid, "(RFC822)")
                    raw_email = msg_data[0][1]
                    msg = email.message_from_bytes(raw_email)

                    subject = msg.get("Subject", "")
                    sender = msg.get("From", "")

                    # Extract email body
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                body += part.get_payload(decode=True).decode(errors="ignore")
                    else:
                        body = msg.get_payload(decode=True).decode(errors="ignore")
                    
                    # Extract URLs
                    urls = extract_urls_from_text(body)
                    
                    # Run ML on each URL
                    url_results = []
                    max_prob = 0.0

                    for u in urls:
                        X_input = extract_features_from_url(u)
                        pred = model.predict(X_input)[0]
                        proba = model.predict_proba(X_input)[0][1]

                        if proba > max_prob:
                            max_prob = proba

                        url_results.append({
                            "url": u,
                            "prediction": "Phishing" if pred == 1 else "Legitimate",
                            "prob": round(float(proba) * 100, 2),
                            "risk": get_risk_level(proba, pred),
                        })
                        
                    # Email-level scoring (basic heuristics)

                    email_risk = get_risk_level(
                        max_prob,
                        1 if max_prob >= 0.5 else 0
                    )

                    results.append({
                        "subject": subject,
                        "sender": sender,
                        "num_urls": len(urls),
                        "email_risk": email_risk,
                        "urls": url_results,
                    })

            except Exception as e:
                error = str(e)

    return render(request, "scan_inbox.html", {
        "results": results,
        "error": error
    })
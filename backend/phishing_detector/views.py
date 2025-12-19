from pathlib import Path
import joblib
from django.shortcuts import render, redirect
from datetime import datetime
import pandas as pd
import re
import imaplib
import email
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required

# -------------------------
# Registration
# -------------------------
def register_view(request):
    if request.user.is_authenticated:
        return redirect('detect_url')

    if request.method == "POST":
        username = request.POST.get("username")
        email_input = request.POST.get("email")
        password = request.POST.get("password")

        if User.objects.filter(username=username).exists():
            return render(request, "register.html", {"error": "Username already exists"})

        user = User.objects.create_user(username=username, email=email_input, password=password)
        login(request, user)  # Automatically log in after registration
        return redirect("detect_url")

    return render(request, "register.html")

# -------------------------
# Login
# -------------------------
def login_view(request):
    if request.user.is_authenticated:
        return redirect('detect_url')

    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect("detect_url")  # Redirect to home page after login
        return render(request, "login.html", {"error": "Invalid credentials"})

    return render(request, "login.html")

# -------------------------
# Logout
# -------------------------
def logout_view(request):
    logout(request)
    return redirect("login")

# -------------------------
# Paths and model loading
# -------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR.parent / "ml_model" / "phishing_model.pkl"

model = joblib.load(MODEL_PATH)

scan_logs = []

# -------------------------
# Utility functions
# -------------------------
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
    return reasons[:3]

def get_risk_level(prob, pred):
    if pred == 0:
        if prob < 0.25:
            return "Low"
        elif prob < 0.5:
            return "Medium"
        else:
            return "Medium"
    if prob >= 0.8:
        return "High"
    elif prob >= 0.45:
        return "Medium"
    else:
        return "Low"

def extract_features_from_url(url):
    features = {
        "length_url": len(url),
        "nb_dots": url.count("."),
        "nb_hyphens": url.count("-"),
        "nb_at": url.count("@"),
        "nb_slash": url.count("/"),
        "nb_qm": url.count("?"),
        "nb_and": url.count("&"),
        "nb_percent": url.count("%"),
        "nb_eq": url.count("="),
    }
    return pd.DataFrame([features])

def extract_urls_from_text(text):
    return re.findall(r'https?://[^\s]+', text)

# -------------------------
# ML Views
# -------------------------
@login_required(login_url="login")
def detect_url(request):
    url = ""
    email_text = ""
    prediction = None
    prob = None
    risk = None
    reasons = []

    if request.method == "POST":
        url = request.POST.get("url", "").strip()
        email_text = request.POST.get("email_text", "").strip()

        urls_to_scan = []
        if url:
            urls_to_scan.append(url)
        if email_text:
            urls_to_scan.extend(extract_urls_from_text(email_text))

        for u in urls_to_scan:
            X_input = extract_features_from_url(u)
            pred = model.predict(X_input)[0]
            proba = model.predict_proba(X_input)[0][1]

            reasons = analyze_url(u)

            prob_percent = round(float(proba) * 100, 2)
            if pred == 1 or reasons:
                prediction = "Phishing" if prob_percent >= 50 else "Suspicious"
            else:
                prediction = "Legitimate"

            risk = get_risk_level(proba, pred)

            scan_logs.insert(0, {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "url": u,
                "prediction": prediction,
                "prob": prob_percent,
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

# -------------------------
# Inbox Scan
# -------------------------
@login_required(login_url="login")
def scan_inbox(request):
    results = []
    error = None

    if request.method == "POST":
        imap_server = request.POST.get("imap_server", "imap.gmail.com")
        email_account = request.POST.get("email_account", "").strip()
        app_password = request.POST.get("app_password", "").strip()
        num_emails = int(request.POST.get("num_emails", 10))

        if not email_account or not app_password:
            error = "Email and app password are required."
        else:
            try:
                mail = imaplib.IMAP4_SSL(imap_server)
                mail.login(email_account, app_password)
                mail.select("inbox", readonly=True)

                status, messages = mail.search(None, "ALL")
                email_ids = messages[0].split()[-num_emails:]

                for eid in reversed(email_ids):
                    _, msg_data = mail.fetch(eid, "(RFC822)")
                    raw_email = msg_data[0][1]
                    msg = email.message_from_bytes(raw_email)

                    subject = msg.get("Subject", "")
                    sender = msg.get("From", "")

                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                body += part.get_payload(decode=True).decode(errors="ignore")
                    else:
                        body = msg.get_payload(decode=True).decode(errors="ignore")

                    urls = extract_urls_from_text(body)
                    url_results = []
                    url_risks = []

                    for u in urls:
                        X_input = extract_features_from_url(u)
                        pred = model.predict(X_input)[0]
                        proba = model.predict_proba(X_input)[0][1]

                        # Cap probability to reduce overconfidence
                        if proba > 0.95:
                            proba = 0.95

                        risk = get_risk_level(proba, pred)

                        url_results.append({
                            "url": u,
                            "prediction": "Phishing" if pred == 1 else "Legitimate",
                            "prob": round(float(proba) * 100, 2),
                            "risk": risk,
                        })

                        url_risks.append(risk)

                    # Aggregate URL risks to determine email-level risk
                    if "High" in url_risks:
                        email_risk = "High"
                    elif "Medium" in url_risks:
                        email_risk = "Medium"
                    else:
                        email_risk = "Low"

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
from pathlib import Path
import joblib
from django.shortcuts import render

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR.parent / "ml_model" / "phishing_model.pkl"
VEC_PATH = BASE_DIR.parent / "ml_model" / "vectorizer.pkl"

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VEC_PATH)

def detect_url(request):
    prediction = None
    prob = None
    url = ""

    if request.method == "POST":
        url = request.POST.get("url", "")
        if url.strip():
            X_vec = vectorizer.transform([url])
            pred = model.predict(X_vec)[0]
            proba = model.predict_proba(X_vec)[0].max()

            if pred == 1:
                prediction = "Phishing / Suspicious"
            else:
                prediction = "Legitimate / Safe (still be cautious)"

            prob = round(float(proba) * 100, 2)

    return render(request, "detect_url.html", {
        "prediction": prediction,
        "prob": prob,
        "url": url,
    })

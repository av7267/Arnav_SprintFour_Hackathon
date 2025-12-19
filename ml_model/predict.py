import joblib
import os

# Load the saved model and vectorizer
model_path = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')
vectorizer_path = os.path.join(os.path.dirname(__file__), 'vectorizer.pkl')

model = joblib.load(model_path)
vectorizer = joblib.load(vectorizer_path)

def detect_phishing(email_text: str) -> bool:
    """
    Detects if the given email text is phishing.
    Returns True if phishing, False otherwise.
    """
    features = vectorizer.transform([email_text])
    prediction = model.predict(features)
    return bool(prediction[0])
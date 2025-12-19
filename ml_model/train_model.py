import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
import joblib
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
data_path = BASE_DIR / "data" / "dataset_phishing.csv"

df = pd.read_csv(data_path)

# Use the raw URL as text and 'status' as label
TEXT_COL = "url"
LABEL_COL = "status"

# Map labels: legitimate -> 0, phishing -> 1
df[LABEL_COL] = df[LABEL_COL].map({"legitimate": 0, "phishing": 1})

X = df[TEXT_COL].astype(str)
y = df[LABEL_COL]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    max_features=5000
)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

model = LogisticRegression(max_iter=1000)
model.fit(X_train_vec, y_train)

print(classification_report(y_test, model.predict(X_test_vec)))

joblib.dump(vectorizer, BASE_DIR / "ml_model" / "vectorizer.pkl")
joblib.dump(model, BASE_DIR / "ml_model" / "phishing_model.pkl")
print("Saved model and vectorizer.")

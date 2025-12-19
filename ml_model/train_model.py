import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
from pathlib import Path
from xgboost import XGBClassifier

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "data" / "dataset_phishing.csv"
MODEL_PATH = BASE_DIR / "ml_model" / "phishing_model.pkl"

# Load dataset
df = pd.read_csv(DATA_PATH)

# Target column
LABEL_COL = "status"
df[LABEL_COL] = df[LABEL_COL].map({"legitimate": 0, "phishing": 1})

# Select numeric features
FEATURES = [
    "length_url",
    "nb_dots",
    "nb_hyphens",
    "nb_at",
    "nb_slash",
    "nb_qm",
    "nb_and",
    "nb_percent",
    "nb_eq"
]

X = df[FEATURES]
y = df[LABEL_COL]

# Handle missing or invalid values
X.fillna(0, inplace=True)
X.replace(-1, 0, inplace=True)

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# XGBoost model
model = XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="logloss",
    use_label_encoder=False,
    random_state=42
)

# Train the model
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("=== Classification Report ===")
print(classification_report(y_test, y_pred))

# Save trained model
joblib.dump(model, MODEL_PATH)
print(f"XGBoost model saved to: {MODEL_PATH}")
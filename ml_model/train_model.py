import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import joblib

# Load dataset
df = pd.read_csv('data/emails.csv')  # Ensure this path is correct
df['label'] = df['label'].map({'ham': 0, 'spam': 1})
df = df.dropna(subset=['label'])  # Remove rows with missing labels
df['label'] = df['label'].astype(int)  # Ensure labels are integers
print(df['label'].value_counts())  # Optional: Show label distribution

# Convert text to features
vectorizer = TfidfVectorizer(stop_words='english')
X = vectorizer.fit_transform(df['text'])
y = df['label']

# Train the model
model = MultinomialNB()
model.fit(X, y)

# Save model and vectorizer
joblib.dump(model, 'ml_model/phishing_model.pkl')
joblib.dump(vectorizer, 'ml_model/vectorizer.pkl')

print("✅ Model and vectorizer saved.")
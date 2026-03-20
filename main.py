import pandas as pd
import re
import nltk
import pickle
import os

from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import classification_report, accuracy_score

# Download NLTK data
nltk.download('punkt')
nltk.download('stopwords')

# Load dataset
data = pd.read_csv("data/raw_dataset/phishing_email.csv")

print("Dataset loaded successfully")
print(data.columns)

stop_words = set(stopwords.words('english'))

# -----------------------------
# TEXT CLEANING
# -----------------------------

def clean_text(text):

    text = str(text).lower()

    # keep url indicator
    text = re.sub(r"http\S+", "url", text)

    text = re.sub(r"[^a-z\s]", "", text)

    tokens = word_tokenize(text)

    tokens = [w for w in tokens if w not in stop_words]

    return " ".join(tokens)

data["clean_text"] = data["text_combined"].apply(clean_text)

# -----------------------------
# RULE BASED SYSTEM
# -----------------------------

urgency_words = [
    "urgent", "immediately", "action required", "verify", "suspended"
]

credential_words = [
    "password", "login", "account", "bank", "security", "confirm"
]

def rule_based_score(text):

    score = 0

    for word in urgency_words:
        if word in text:
            score += 2

    for word in credential_words:
        if word in text:
            score += 2

    if "url" in text:
        score += 3

    if text.count("!") >= 3:
        score += 1

    if len(text.split()) < 20:
        score += 1

    return score

data["rule_score"] = data["clean_text"].apply(rule_based_score)

data["rule_prediction"] = data["rule_score"].apply(
    lambda x: 1 if x >= 5 else 0
)

# -----------------------------
# MACHINE LEARNING MODEL
# -----------------------------

X = data["clean_text"]
y = data["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

vectorizer = TfidfVectorizer(max_features=5000)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

ml_model = MultinomialNB()

ml_model.fit(X_train_vec, y_train)

ml_predictions = ml_model.predict(X_test_vec)

print("ML Accuracy:", accuracy_score(y_test, ml_predictions))

print(classification_report(y_test, ml_predictions))

# -----------------------------
# HYBRID MODEL
# -----------------------------

def hybrid_decision(rule_score, ml_pred):

    if rule_score >= 5:
        return 1
    else:
        return ml_pred

rules_test = data.loc[X_test.index, "rule_score"].reset_index(drop=True)

hybrid_predictions = [
    hybrid_decision(rules_test[i], ml_predictions[i])
    for i in range(len(ml_predictions))
]

print("Hybrid Accuracy:", accuracy_score(y_test, hybrid_predictions))

print(classification_report(y_test, hybrid_predictions))

# -----------------------------
# SAVE MODEL
# -----------------------------

os.makedirs("model", exist_ok=True)

pickle.dump(ml_model, open("model/phishing_model.pkl", "wb"))
pickle.dump(vectorizer, open("model/vectorizer.pkl", "wb"))

print("Model and vectorizer saved successfully!")
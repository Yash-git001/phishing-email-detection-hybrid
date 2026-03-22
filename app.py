import streamlit as st
import pickle
import re
import tldextract
import requests

# ------------------------------
# Page configuration
# ------------------------------

st.set_page_config(
    page_title="Phishing Email Detection Tool",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Phishing Email Detection Tool")
st.write("Hybrid phishing detection using Machine Learning + Rule Based Analysis")

# ------------------------------
# Load ML model
# ------------------------------

try:
    model = pickle.load(open("model/phishing_model.pkl", "rb"))
vectorizer = pickle.load(open("model/vectorizer.pkl", "rb"))

except:
    model = None
    vectorizer = None
    st.error(f"Model not loaded: {e}")

# ------------------------------
# Helper Functions
# ------------------------------

def extract_links(text):
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)


def check_domain(domain):
    url = f"https://dns.google/resolve?name={domain}"
    try:
        response = requests.get(url)
        data = response.json()
        return "Answer" in data
    except:
        return False


def suspicious_domain_check(domain):

    risky_words = [
        "secure",
        "login",
        "verify",
        "update",
        "account",
        "bank",
        "confirm"
    ]

    for word in risky_words:
        if word in domain:
            return True

    return False


def analyze_sender(text):

    email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    emails = re.findall(email_pattern, text)

    suspicious = []

    for e in emails:
        if "gmail" in e or "yahoo" in e or "outlook" in e:
            suspicious.append(e)

    return emails, suspicious


def rule_based_score(text):

    score = 0
    reasons = []

    keywords = [
        "urgent",
        "verify your account",
        "login immediately",
        "update account",
        "suspended",
        "click here",
        "confirm password"
    ]

    for word in keywords:
        if word in text.lower():
            score += 1
            reasons.append(f"Keyword detected: {word}")

    links = extract_links(text)

    if len(links) > 0:
        score += 1
        reasons.append("Email contains links")

    if "@" in text and "http" in text:
        score += 1
        reasons.append("Possible phishing structure detected")

    return score, reasons


# ------------------------------
# Email Input Section
# ------------------------------

col1, col2 = st.columns([10,1])

with col1:
    email_text = st.text_area(
        "Paste Email Content",
        height=250,
        placeholder="Paste the suspicious email here..."
    )

with col2:
    if st.button("🗑️"):
        st.session_state.clear()
        st.rerun()


# ------------------------------
# File Upload
# ------------------------------

uploaded_file = st.file_uploader("Upload Email File (.txt or .eml)", type=["txt","eml"])

if uploaded_file:

    email_text = uploaded_file.read().decode("utf-8")
    st.success("Email file loaded successfully")

# ------------------------------
# Analyze Button
# ------------------------------

if st.button("🔍 Analyze Email"):

    if not email_text.strip():
        st.warning("Please enter or upload an email first")
    else:

        st.subheader("Detection Result")

        # ------------------------------
        # ML Detection
        # ------------------------------

        if model and vectorizer:

            vector = vectorizer.transform([email_text])
            probability = model.predict_proba(vector)[0][1]
            phishing_percent = int(probability * 100)

        else:
            phishing_percent = 0

        st.progress(phishing_percent)

        st.write(f"Phishing Probability: **{phishing_percent}%**")

        # Risk level

        if phishing_percent >= 75:
            st.error("HIGH RISK EMAIL")
        elif phishing_percent >= 40:
            st.warning("MEDIUM RISK EMAIL")
        else:
            st.success("LOW RISK EMAIL")

        # ------------------------------
        # Rule Based Analysis
        # ------------------------------

        score, reasons = rule_based_score(email_text)

        # ------------------------------
        # Link Analysis
        # ------------------------------

        links = extract_links(email_text)
        suspicious_domains = []
        verified_domains = []

        for link in links:

            domain = tldextract.extract(link).domain

            if check_domain(domain):
                verified_domains.append(domain)
            else:
                suspicious_domains.append(domain)

            if suspicious_domain_check(domain):
                suspicious_domains.append(domain)

        # ------------------------------
        # Sender Analysis
        # ------------------------------

        emails_found, suspicious_senders = analyze_sender(email_text)

        # ------------------------------
        # Detailed Analysis Section
        # ------------------------------

        with st.expander("Show Detailed Analysis"):

            st.subheader("Rule Based Detection")

            st.write("Rule Score:", score)

            for r in reasons:
                st.write("•", r)

            st.subheader("Link Analysis")

            if links:
                st.write("Links Found:")
                for link in links:
                    st.write(link)
            else:
                st.write("No links detected")

            if suspicious_domains:
                st.warning(f"Suspicious Domains: {suspicious_domains}")

            if verified_domains:
                st.success(f"Verified Domains: {verified_domains}")

            st.subheader("Sender Analysis")

            if emails_found:
                st.write("Emails Found:", emails_found)

            if suspicious_senders:
                st.warning("Suspicious sender addresses detected")

        # ------------------------------
        # Final Security Advice
        # ------------------------------

        st.subheader("Security Recommendation")

        if phishing_percent > 60:
            st.error(
                "This email is likely a phishing attempt. Do NOT click links or provide credentials."
            )
        else:
            st.success("No major phishing indicators detected.")

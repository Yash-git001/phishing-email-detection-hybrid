import streamlit as st
import pickle
import re
import os
import pandas as pd
import subprocess
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
# Auto train model if pkl missing
# ------------------------------
if not os.path.exists("model/phishing_model.pkl") or not os.path.exists("model/vectorizer.pkl"):
    st.warning("⚙️ Model not found. Training now for the first time, this may take a few minutes...")
    with st.spinner("Downloading dataset and training model..."):
        subprocess.run(["python", "main.py"])
    st.success("Model trained and saved! Reloading...")
    st.rerun()

# ------------------------------
# Load ML model
# ------------------------------
try:
    model = pickle.load(open("model/phishing_model.pkl", "rb"))
    vectorizer = pickle.load(open("model/vectorizer.pkl", "rb"))
except Exception as e:
    model = None
    vectorizer = None
    st.error(f"Model failed to load: {e}")

# ------------------------------
# Helper Functions
# ------------------------------
def extract_links(text):
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)

def check_domain(domain):
    url = f"https://dns.google/resolve?name={domain}"
    try:
        response = requests.get(url, timeout=5)
        data = response.json()
        return "Answer" in data
    except:
        return False

def suspicious_domain_check(domain):
    risky_words = ["secure", "login", "verify", "update", "account", "bank", "confirm"]
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
        "urgent", "verify your account", "login immediately",
        "update account", "suspended", "click here", "confirm password"
    ]
    for word in keywords:
        if word in text.lower():
            score += 1
            reasons.append(f"Keyword detected: '{word}'")

    links = extract_links(text)
    if len(links) > 0:
        score += 1
        reasons.append(f"{len(links)} link(s) found in email")

    if "@" in text and "http" in text:
        score += 1
        reasons.append("Possible phishing structure detected")

    return score, reasons

# ------------------------------
# Session State for text clear
# ------------------------------
if "email_text" not in st.session_state:
    st.session_state.email_text = ""

def clear_text():
    st.session_state.email_text = ""
# ------------------------------
# Email Input Section
# ------------------------------
col1, col2 = st.columns([10, 1])

with col1:
    email_text = st.text_area(
        "Paste Email Content",
        height=250,
        placeholder="Paste the suspicious email here...",
        key="email_text"
    )

with col2:
    st.button("🗑️", on_click=clear_text)

# ------------------------------
# File Upload
# ------------------------------
uploaded_file = st.file_uploader("Upload Email File (.txt or .eml)", type=["txt", "eml"])
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
            st.error("ML model unavailable, showing rule-based result only.")

        st.progress(phishing_percent / 100)
        st.write(f"Phishing Probability: **{phishing_percent}%**")

        # Risk level
        if phishing_percent >= 75:
            st.error("🚨 HIGH RISK EMAIL")
        elif phishing_percent >= 40:
            st.warning("⚠️ MEDIUM RISK EMAIL")
        else:
            st.success("✅ LOW RISK EMAIL")

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
            if suspicious_domain_check(domain):
                if domain not in suspicious_domains:
                    suspicious_domains.append(domain)
            elif check_domain(domain):
                if domain not in verified_domains:
                    verified_domains.append(domain)

        # ------------------------------
        # Sender Analysis
        # ------------------------------
        emails_found, suspicious_senders = analyze_sender(email_text)

        # ------------------------------
        # Detailed Analysis Report
        # ------------------------------
        with st.expander("🔎 Detailed Analysis Report"):

            st.markdown("---")

            # --- Rule Based ---
            st.markdown("### 📋 Rule-Based Detection")
            col_a, col_b = st.columns([1, 3])
            with col_a:
                st.metric(label="Rule Score", value=f"{score} / 10")
            with col_b:
                if reasons:
                    for r in reasons:
                        st.markdown(f"🔸 {r}")
                else:
                    st.success("No rule-based indicators found.")

            st.markdown("---")

            # --- Link Analysis ---
            st.markdown("### 🔗 Link Analysis")
            if links:
                st.write(f"**{len(links)} link(s) detected:**")
                for link in links:
                    st.code(link)
            else:
                st.info("No links found in this email.")

            if suspicious_domains:
                st.error(f"⚠️ Suspicious Domains: {', '.join(suspicious_domains)}")
            if verified_domains:
                st.success(f"✅ Verified Domains: {', '.join(verified_domains)}")

            st.markdown("---")

            # --- Sender Analysis ---
            st.markdown("### 📧 Sender Analysis")
            if emails_found:
                st.write(f"**Email addresses found:** {', '.join(emails_found)}")
                if suspicious_senders:
                    st.warning("⚠️ Free email provider detected (Gmail/Yahoo/Outlook) — commonly used in phishing")
                else:
                    st.success("✅ No suspicious sender patterns detected.")
            else:
                st.info("No sender email addresses found in this email.")

            st.markdown("---")

            # --- Summary Table ---
            st.markdown("### 📊 Detection Summary")
            summary_data = {
                "Check": [
                    "ML Phishing Probability",
                    "Rule-Based Score",
                    "Suspicious Links",
                    "Suspicious Senders"
                ],
                "Result": [
                    f"{phishing_percent}%",
                    f"{score} / 10",
                    f"{len(suspicious_domains)} found" if suspicious_domains else "None",
                    f"{len(suspicious_senders)} found" if suspicious_senders else "None"
                ],
                "Status": [
                    "🔴 High" if phishing_percent >= 75 else "🟡 Medium" if phishing_percent >= 40 else "🟢 Low",
                    "🔴 High" if score >= 5 else "🟡 Medium" if score >= 3 else "🟢 Low",
                    "🔴 Suspicious" if suspicious_domains else "🟢 Clean",
                    "🟡 Caution" if suspicious_senders else "🟢 Clean"
                ]
            }
            st.table(pd.DataFrame(summary_data))

        # ------------------------------
        # Final Security Advice
        # ------------------------------
        st.subheader("Security Recommendation")
        if phishing_percent > 60 or score >= 5:
            st.error("🚫 This email is likely a phishing attempt. Do NOT click links or provide credentials.")
        else:
            st.success("✅ No major phishing indicators detected. Stay cautious regardless.")

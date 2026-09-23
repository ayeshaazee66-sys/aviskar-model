from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse
import re

app = Flask(__name__)

# Allow requests from your website during development/testing
CORS(app)


# -----------------------------
# Scam/Risk Detection Function
# -----------------------------

def check_risk(data):

    risk_score = 0
    reasons = []

    message = str(data.get("message", "")).lower()
    website = str(data.get("website", "")).lower()
    location = str(data.get("location", "")).lower()

    # 1. Suspicious words / phrases
    scam_words = [
        "urgent",
        "otp",
        "password",
        "click here",
        "winner",
        "prize",
        "send money",
        "verify your account",
        "limited time",
        "claim now"
        "90% off",
        "100% off",
        "huge discount",
        "exclusive offer",
        "free iphone",
        "too good to be true"
    ]

    for word in scam_words:
        if word in message:
            risk_score += 10
            reasons.append(
                "Suspicious phrase detected: " + word
            )

    # 2. Suspicious website patterns
    suspicious_domains = [
        ".xyz",
        ".top",
        ".click",
        ".tk"
    ]

    for domain in suspicious_domains:
        if domain in website:
            risk_score += 20
            reasons.append(
                "Website uses a potentially suspicious domain."
            )

    # 3. Transaction amount
    try:
        amount = float(data.get("amount", 0))

        if amount >= 50000:
            risk_score += 20
            reasons.append(
                "High transaction amount."
            )

    except (ValueError, TypeError):
        pass

    # 4. Location
    if location:
        reasons.append("Delivery location received.")

    # Never allow score above 100
    risk_score = min(risk_score, 100)

    # Determine risk level
    if risk_score >= 60:
        level = "HIGH RISK"
    elif risk_score >= 30:
        level = "SUSPICIOUS"
    else:
        level = "LOW RISK"

    return {
        "score": risk_score,
        "level": level,
        "reasons": reasons
    }
# -----------------------------
# URL Scam Detection
# -----------------------------

def analyze_url(url):

    risk_score = 0
    reasons = []

    url = str(url).strip().lower()

    if not url:
        return {
            "score": 0,
            "level": "LOW RISK",
            "reasons": ["No URL was provided."]
        }

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc

        domain = domain.split("@")[-1].split(":")[0]

    except Exception:
        return {
            "score": 100,
            "level": "HIGH RISK",
            "reasons": ["The URL format is invalid."]
        }

    # 1. HTTPS check
    if parsed.scheme != "https":
        risk_score += 15
        reasons.append("Website does not use HTTPS.")

    # 2. Suspicious domain extensions
    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq"
    ]

    for tld in suspicious_tlds:
        if domain.endswith(tld):
            risk_score += 20
            reasons.append(
                "Potentially suspicious domain extension detected."
            )
            break

    # 3. IP address instead of domain
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if re.match(ip_pattern, domain):
        risk_score += 25
        reasons.append(
            "Website uses an IP address instead of a normal domain name."
        )

    # 4. @ symbol
    if "@" in url:
        risk_score += 25
        reasons.append(
            "URL contains '@', which can be used to disguise the real destination."
        )

    # 5. Very long URL
    if len(url) > 100:
        risk_score += 10
        reasons.append("URL is unusually long.")

    # 6. Suspicious words
    suspicious_words = [
        "login",
        "verify",
        "account",
        "password",
        "urgent",
        "free",
        "winner",
        "prize",
        "claim",
        "payment",
        "otp"
    ]

    for word in suspicious_words:
        if word in url:
            risk_score += 5
            reasons.append(
                "Suspicious word found in URL: " + word
            )

    risk_score = min(risk_score, 100)

    # Risk level
    if risk_score >= 60:
        level = "HIGH RISK"
    elif risk_score >= 30:
        level = "SUSPICIOUS"
    else:
        level = "LOW RISK"

    if not reasons:
        reasons.append(
            "No obvious URL-based scam indicators were detected."
        )

    return {
        "url": url,
        "domain": domain,
        "score": risk_score,
        "level": level,
        "reasons": reasons
    }


# -----------------------------
# URL Analysis API
# -----------------------------

@app.route("/api/analyze-url", methods=["POST"])
def analyze_url_api():

    data = request.get_json(silent=True) or {}

    url = data.get("url", "")

    result = analyze_url(url)

    return jsonify(result)

# -----------------------------
# Main Website
# -----------------------------

@app.route("/")
def home():
    return render_template("index.html")
# -----------------------------
# About Page
# -----------------------------

@app.route("/about")
def about():
    return render_template("about.html")

# -----------------------------
# Tips Page
# -----------------------------

@app.route("/tips")
def tips():
    return render_template("tips.html")
# -----------------------------
# Report Page
# -----------------------------

@app.route("/report")
def report():
    return render_template("report.html")

# -----------------------------
# General Scam Detection API
# -----------------------------

@app.route("/check", methods=["POST"])
def check():

    data = request.get_json(silent=True) or {}

    result = check_risk(data)

    return jsonify(result)


# -----------------------------
# Pearl and Pouch Checkout API
# -----------------------------

@app.route("/checkout-risk", methods=["POST"])
def checkout_risk():

    data = request.get_json(silent=True) or {}

    # Run scam/risk detection
    result = check_risk(data)

    # High-risk transactions are blocked
    if result["level"] == "HIGH RISK":
        result["allow_order"] = False
        result["action"] = "BLOCK"
        result["message"] = (
            "Order blocked because the transaction "
            "was identified as high risk."
        )

    else:
        result["allow_order"] = True
        result["action"] = "ALLOW"
        result["message"] = (
            "Transaction passed the risk check."
        )

    return jsonify(result)


# -----------------------------
# Run Flask Server
# -----------------------------
# -----------------------------
# About Page
# -----------------------------


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
# 🔐 Phishing URL Detector

A Python-based cybersecurity tool that analyzes URLs for common phishing indicators and assigns a risk score from **0–100**.

The project includes a command-line detector, Flask web dashboard, scan history, and a REST API with input validation and rate limiting.

> **Note:** This is a heuristic detection tool. It does not guarantee that a URL is safe or malicious.

---

## 🎯 Project Overview

Phishing attacks commonly use deceptive URLs to trick users into revealing sensitive information such as passwords, banking details, and account credentials.

This project was built to demonstrate how a defensive cybersecurity tool can identify suspicious characteristics in URLs and provide an explainable risk assessment.

The detector examines multiple URL characteristics and combines them into a risk score.

---

## 🚀 Features

### URL Analysis

* HTTPS/HTTP detection
* IP address detection
* Suspicious keyword detection
* Suspicious domain-word detection
* Trusted-domain checking
* Suspicious TLD detection
* URL shortener detection
* Punycode detection
* `@` symbol detection
* Subdomain analysis
* Domain hyphen analysis
* Domain number analysis
* URL complexity analysis
* Query parameter analysis
* Deep path detection
* Non-standard port detection
* URL encoding detection

### Risk Scoring

The detector produces a score from:

```text
0–100
```

and classifies URLs as:

| Score | Verdict |
| --- | --- |
| 0–39 | LOW RISK |
| 40–69 | SUSPICIOUS |
| 70–100 | HIGH RISK |

### Web Dashboard

The Flask dashboard provides:

* URL scanning
* Risk score display
* Verdict display
* Detection indicators
* Scan statistics
* Scan history

### REST API

The project provides:

```text
POST /api/analyze
```

The API includes:

* JSON input
* Input validation
* Malformed URL validation
* Data-type validation
* JSON responses
* Rate limiting

The API is limited to:

```text
10 requests per minute per IP address
```

---

## 🛠️ Technologies

* Python
* Flask
* Flask-Limiter
* HTML
* CSS
* CSV
* Regular Expressions
* URL Parsing

---

## 🧠 Detection Methodology

The detector uses a **heuristic scoring approach** rather than machine learning.

Different URL characteristics contribute points to the overall risk score.

Examples of suspicious characteristics include:

```text
HTTP instead of HTTPS
IP address used as the hostname
Suspicious keywords
Multiple hyphens
Suspicious TLDs
URL shorteners
Punycode
Suspicious domain words
Deep URL paths
Excessive query parameters
Non-standard ports
```

The individual indicators are combined to produce the final risk score.

---

## 🔌 REST API

### Endpoint

```text
POST /api/analyze
```

### Example Request

```json
{
    "url": "https://example.com"
}
```

### Example Response

```json
{
    "url": "https://example.com",
    "score": 0,
    "verdict": "LOW RISK",
    "indicators": [
        "Uses HTTPS",
        "Domain is not listed in the local trusted-domain database"
    ],
    "timestamp": "2026-09-11 09:15:53"
}
```

### Invalid Input Example

```json
{
    "url": 12345
}
```

Response:

```json
{
    "error": "URL must be a string."
}
```

---

## 🛡️ API Security

The API implements rate limiting using Flask-Limiter.

Current configuration:

```text
10 requests per minute per IP address
```

Requests exceeding the limit receive:

```text
HTTP 429 Too Many Requests
```

This helps reduce excessive requests against the analysis endpoint.

---

## 🧪 Testing

The API was tested using PowerShell.

### Valid URL

```text
https://example.com
```

Result:

```text
Score: 0
Verdict: LOW RISK
```

### Malformed URL

```text
http://
```

Result:

```text
Score: 100
Verdict: HIGH RISK
Indicator: Invalid or malformed URL
```

### Invalid Domain

```text
not-a-real-url
```

Result:

```text
Score: 100
Verdict: HIGH RISK
Indicator: Invalid domain name
```

### Suspicious URL

```text
http://paypal-login-verify-account.com
```

Result:

```text
Score: 55
Verdict: SUSPICIOUS
```

Detected indicators included:

```text
HTTP instead of HTTPS
Suspicious keywords
Multiple domain hyphens
Domain not listed in trusted-domain database
```

### Invalid Data Type

```json
{
    "url": 12345
}
```

Result:

```text
HTTP 400
URL must be a string.
```

### Rate Limiting

The API was tested with 11 consecutive requests.

Result:

```text
Requests 1–10 → Accepted
Request 11 → HTTP 429 TOO MANY REQUESTS
```

---

## 📁 Project Structure

```text
phishing-url-detector/
│
├── app.py
├── detector.py
├── 
├── scan_history.csv
├── README.md
│
├── templates/
│   └── index.html
│
└── .env
```

---

## ▶️ Installation

Clone the repository:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

Navigate into the project:

```bash
cd phishing-url-detector
```

Install dependencies:

```bash
pip install flask flask-limiter
```

Run the application:

```bash
python app.py
```

Open the web application:

```text
http://127.0.0.1:5000
```

---

## 💻 Example CLI Usage

The detector can also be executed directly:

```bash
python detector.py
```

The CLI provides options to:

```text
1. Scan URL
2. View Scan History
3. Exit
```

---

## ⚠️ Limitations

This project uses heuristic analysis and should not be considered a definitive phishing detection system.

A legitimate URL may contain suspicious characteristics, while a sophisticated phishing URL may avoid obvious indicators.

The trusted-domain list is also local and manually maintained.

The tool does not currently perform:

* Real-time domain reputation checks
* WHOIS analysis
* DNS reputation analysis
* Threat-intelligence API lookups
* Website content analysis
* Machine-learning classification

---

## 🔮 Future Improvements

Potential future improvements include:

* Threat intelligence API integration
* WHOIS/domain-age analysis
* DNS analysis
* VirusTotal integration
* Machine-learning classification
* URL reputation databases
* Authentication for the API
* Persistent rate-limit storage
* API documentation with Swagger/OpenAPI
* Automated unit tests
* Docker deployment
* Cloud deployment
* Improved logging and monitoring

---

## 🎓 Cybersecurity Skills Demonstrated

This project demonstrates practical experience with:

* Python programming
* Secure input validation
* Web application development
* REST API development
* API security
* Rate limiting
* URL parsing
* Threat detection logic
* Risk scoring
* Defensive security concepts
* Log/history management
* Flask development
* Security-focused testing

---

## 👨‍💻 Author

**Eila Lotesiro Lloyd**

Cybersecurity & Forensics Student

Interested in:

* SOC Analysis
* Cybersecurity
* Digital Forensics
* Security Operations
* GRC
* Threat Detection

---

## ⚠️ Disclaimer

This project is intended for **educational and defensive cybersecurity purposes**.

The results generated by this tool are heuristic assessments and should not be treated as definitive security verdicts.

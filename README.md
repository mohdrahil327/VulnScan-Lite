# 🛡️ VulnScan Lite: Full-Stack Security Scanner

VulnScan Lite is a web-based vulnerability assessment tool designed to help developers quickly audit their website's security posture. It analyzes SSL certificate health and critical HTTP security headers in real-time.

## 🚀 System Architecture
- **Backend:** FastAPI (Python) - Handles asynchronous scanning logic.
- **Frontend:** React.js (JavaScript) - Provides a dynamic, icon-based dashboard.
- **Scanning Engine:** Custom Python modules using `ssl`, `socket`, and `requests`.

## ✨ Key Features
- **Live SSL Audit:** Checks validity, issuer, and calculates days until expiry.
- **Header Analysis:** Scans for missing security layers like CSP, HSTS, and XSS protection.
- **Dynamic Scoring:** Generates an overall security score (0-100) based on findings.
- **Asynchronous UI:** Users can see the scanning state without the page freezing.

## 🛠️ Installation & Setup

### 1. Backend Setup
```bash
cd Scanlitee
pip install -r requirements.txt
uvicorn app:app --reload

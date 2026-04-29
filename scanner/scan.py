import warnings
from datetime import datetime
from typing import Any

import requests
from bs4 import BeautifulSoup

from .cms import detect_cms
from .headers import analyze_security_headers
from .ssl_inspection import inspect_ssl
from .utils import USER_AGENT, build_remediation_note, get_host_and_port, normalize_url


def _get_grade(score: int) -> str:
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B+"
    if score >= 60:
        return "B"
    if score >= 50:
        return "C"
    return "D"


def _clamp_score(score: int) -> int:
    return max(0, min(score, 100))


def _create_remediation(header_result: dict[str, Any], ssl_result: dict[str, Any], cms_result: dict[str, Any], url: str) -> dict[str, str]:
    remediation = {}

    if header_result["failed"]:
        if "Content-Security-Policy" in header_result["failed"]:
            remediation["Content-Security-Policy"] = (
                "Add a strong CSP header, e.g. `Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.com;`"
            )
        if "X-Frame-Options" in header_result["failed"]:
            remediation["X-Frame-Options"] = (
                "Add `X-Frame-Options: DENY` or `SAMEORIGIN` to prevent clickjacking."
            )
        if "Strict-Transport-Security" in header_result["failed"]:
            remediation["Strict-Transport-Security"] = (
                "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` to enforce HTTPS."
            )

    if not ssl_result["valid"]:
        remediation["TLS"] = (
            "Ensure the site supports HTTPS with a valid certificate. "
            "Use Let's Encrypt or a trusted CA and renew before expiration."
        )
    else:
        if ssl_result["grade"] in ("C", "F"):
            remediation["TLS Cipher"] = (
                "Use modern TLS settings (TLS 1.2+ with ECDHE and AES-GCM/CHACHA20-POLY1305 ciphers)."
            )
        if ssl_result["days_remaining"] is not None and ssl_result["days_remaining"] < 30:
            remediation["TLS Expiration"] = (
                "Renew the certificate before expiration to avoid browser warnings or outages."
            )

    if cms_result["cms"] != "Unknown":
        if cms_result["status"] == "verified" and cms_result["version"]:
            remediation["CMS"] = (
                f"Update {cms_result['cms']} to the latest supported version. "
                "Check plugin and theme updates as well for security patches."
            )
        else:
            remediation["CMS"] = (
                f"Review the {cms_result['cms']} installation and keep it updated. "
                "Remove unused themes and plugins, and harden admin access."
            )

    if url.lower().startswith("http://"):
        remediation["HTTPS"] = (
            "Enable HTTPS and redirect HTTP traffic to HTTPS. "
            "This will protect user data and allow HSTS to work correctly."
        )

    return remediation


def _build_check_list(header_result: dict[str, Any], ssl_result: dict[str, Any]) -> dict[str, list[str]]:
    passed = []
    failed = []
    passed.extend(header_result["passed"])
    failed.extend(header_result["failed"])

    if ssl_result["valid"]:
        passed.append("TLS/SSL Configuration")
    else:
        failed.append("TLS/SSL Configuration")

    return {"passed": passed, "failed": failed}


def scan_website(url: str) -> dict[str, Any]:
    target_url = normalize_url(url)
    warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

    response = requests.get(
        target_url,
        headers={"User-Agent": USER_AGENT},
        timeout=20,
        verify=False,
        allow_redirects=True,
    )

    normalized_headers = {k.lower(): v for k, v in response.headers.items()}
    html = response.text
    header_result = analyze_security_headers(response.headers)
    host, port = get_host_and_port(target_url)
    ssl_result = inspect_ssl(host, port)
    cms_result = detect_cms(response.headers, html)

    vpn_score = header_result["score"]
    if ssl_result["valid"]:
        vpn_score += 25
    else:
        vpn_score -= 15

    if cms_result["cms"] != "Unknown" and cms_result["version"]:
        try:
            major_version = int(cms_result["version"].split(".")[0])
            if major_version < 5 and cms_result["cms"] == "WordPress":
                vpn_score -= 10
        except ValueError:
            pass

    score = _clamp_score(70 + vpn_score)
    grade = _get_grade(score)
    checks = _build_check_list(header_result, ssl_result)
    remediation = _create_remediation(header_result, ssl_result, cms_result, target_url)

    return {
        "scanned_url": target_url,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "score": score,
        "grade": grade,
        "headers": {
            "passed": header_result["passed"],
            "failed": header_result["failed"],
            "details": header_result["details"],
        },
        "ssl": ssl_result,
        "cms": cms_result,
        "checks": checks,
        "remediation": remediation,
    }

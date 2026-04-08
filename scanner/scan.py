import requests
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse


def normalize_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url


def get_header_checks():
    return {
        "Content-Security-Policy": "Add Content-Security-Policy to reduce XSS risks.",
        "X-Frame-Options": "Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
        "Strict-Transport-Security": "Set Strict-Transport-Security header to enforce HTTPS.",
        "Referrer-Policy": "Set Referrer-Policy to same-origin or strict-origin-when-cross-origin.",
        "Permissions-Policy": "Set Permissions-Policy to disable unnecessary powerful APIs."
    }


def check_headers(url):
    result = {
        "passed": [],
        "failed": [],
        "details": {},
        "score": 0
    }

    try:
        response = requests.get(url, timeout=5, verify=False)
        headers = response.headers
        header_checks = get_header_checks()

        for header_name in header_checks:
            if header_name in headers:
                result["passed"].append(header_name)
                result["details"][header_name] = headers.get(header_name)
                result["score"] += 10
            else:
                result["failed"].append(header_name)

        return result

    except Exception as e:
        return {
            "passed": [],
            "failed": list(get_header_checks().keys()),
            "details": {},
            "score": 0,
            "error": str(e)
        }


def check_ssl(url):
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    host = parsed.hostname
    port = parsed.port or 443

    ssl_result = {
        "valid": False,
        "expiry_date": None,
        "issuer": None,
        "cipher": None,
        "protocol": None,
        "error": None
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                ssl_result["issuer"] = dict(x[0] for x in cert.get("issuer", [])) if cert else None
                expiry = cert.get("notAfter")
                if expiry:
                    expiry_dt = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z")
                    ssl_result["expiry_date"] = expiry_dt.isoformat()
                    ssl_result["valid"] = expiry_dt > datetime.utcnow()
                else:
                    ssl_result["expiry_date"] = "unknown"

                cipher_info = ssock.cipher()
                if cipher_info:
                    ssl_result["cipher"] = cipher_info[0]
                    ssl_result["protocol"] = cipher_info[1]

    except ssl.SSLCertVerificationError as e:
        ssl_result["error"] = f"Certificate verification failed: {e}"
    except Exception as e:
        ssl_result["error"] = str(e)

    return ssl_result


def detect_cms(url):
    try:
        normalized = normalize_url(url)
        response = requests.get(normalized, timeout=5, verify=False)
        headers = response.headers
        text = response.text.lower()

        cms = "Unknown"
        version = None

        if "wp-content" in text or "wordpress" in text or "x-powered-by" in headers.get("x-powered-by", "").lower():
            cms = "WordPress"
            if 'generator" content="wordpress' in text:
                version_start = text.find('generator" content="wordpress')
                snippet = text[version_start:version_start + 100]
                start = snippet.find("wordpress")
                if start != -1:
                    version = snippet[start:].split()[1] if len(snippet[start:].split()) > 1 else None

        elif "drupal" in text or "x-powered-by" in headers.get("x-powered-by", "").lower():
            cms = "Drupal"

        elif "shopify" in text:
            cms = "Shopify"

        generator_meta = None
        if "<meta name=\"generator\"" in text:
            generator_meta = text.split("<meta name=\"generator\"")[1].split(">")[0]
            if "wordpress" in generator_meta:
                cms = "WordPress"
            elif "drupal" in generator_meta:
                cms = "Drupal"

        return {
            "cms": cms,
            "version": version,
            "generator_meta": generator_meta,
            "powered_by": headers.get("x-powered-by", "")
        }

    except Exception as e:
        return {
            "cms": "Unknown",
            "version": None,
            "generator_meta": None,
            "powered_by": "",
            "error": str(e)
        }


def get_remediation(details):
    fixes = {}

    header_fixes = get_header_checks()
    for header in details.get("failed", []):
        if header in header_fixes:
            fixes[header] = header_fixes[header]

    if not details.get("ssl", {}).get("valid", True):
        fixes["SSL/TLS"] = "Renew the certificate or fix SSL chain issues. Ensure TLS 1.2+ is enabled."

    cms = details.get("cms", {}).get("cms") or details.get("cms")
    if isinstance(cms, str) and cms == "WordPress":
        fixes["CMS"] = "Update WordPress and plugins to the latest stable versions and remove inactive plugins/themes."

    return fixes


def scan_website(url):
    target = normalize_url(url)

    headers = check_headers(target)
    ssl_data = check_ssl(target)
    cms = detect_cms(target)

    score = headers.get("score", 0)

    # scoring scheme: +10 for present; -10 for missing header
    total_header_checks = len(get_header_checks())
    total_score = score - 10 * (total_header_checks - len(headers.get("passed", [])))

    if ssl_data.get("valid"):
        total_score += 20
    else:
        total_score -= 20

    # clamp 0-100
    total_score = max(0, min(100, total_score))

    if total_score > 90:
        grade = "A+"
    elif total_score > 80:
        grade = "A"
    elif total_score > 70:
        grade = "B+"
    elif total_score > 60:
        grade = "B"
    elif total_score > 50:
        grade = "C"
    else:
        grade = "D"

    remediation = get_remediation({"failed": headers.get("failed", []), "ssl": ssl_data, "cms": cms})

    return {
        "url": target,
        "score": total_score,
        "grade": grade,
        "headers": headers,
        "ssl": ssl_data,
        "cms": cms,
        "remediation": remediation,
        "updated_at": datetime.utcnow().isoformat() + "Z"
    }

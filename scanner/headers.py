from typing import Any

SECURITY_HEADERS = {
    "content-security-policy": {
        "label": "Content-Security-Policy",
        "description": "Helps prevent cross-site scripting and injection attacks.",
        "score": 10,
    },
    "x-frame-options": {
        "label": "X-Frame-Options",
        "description": "Prevents clickjacking by restricting iframe embedding.",
        "score": 10,
    },
    "strict-transport-security": {
        "label": "Strict-Transport-Security",
        "description": "Requires HTTPS and prevents protocol downgrade attacks.",
        "score": 10,
    },
}


def analyze_security_headers(headers: dict[str, Any]) -> dict[str, Any]:
    passed = []
    failed = []
    score = 0
    details = []

    normalized = {k.lower(): v for k, v in headers.items()}

    for key, info in SECURITY_HEADERS.items():
        if key in normalized and normalized[key].strip():
            passed.append(info["label"])
            score += info["score"]
            details.append({"name": info["label"], "status": "present", "value": normalized[key]})
        else:
            failed.append(info["label"])
            score -= info["score"]
            details.append({"name": info["label"], "status": "missing", "value": None})

    return {
        "passed": passed,
        "failed": failed,
        "score": score,
        "details": details,
    }

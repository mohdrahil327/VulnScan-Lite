import ssl
import socket
from datetime import datetime
from typing import Any


def _parse_not_after(not_after: str) -> str:
    try:
        parsed = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        parsed = datetime.strptime(not_after, "%Y%m%d%H%M%SZ")
    return parsed.strftime("%Y-%m-%d")


def _rate_cipher(cipher_name: str, protocol: str) -> str:
    strong_keywords = ["CHACHA20", "AESGCM", "ECDHE"]
    weak_keywords = ["RC4", "MD5", "DES", "3DES", "EXPORT"]

    if protocol == "TLSv1.3":
        return "A"
    if any(word in cipher_name.upper() for word in weak_keywords):
        return "F"
    if any(word in cipher_name.upper() for word in strong_keywords):
        return "B"
    return "C"


def inspect_ssl(host: str, port: int = 443, timeout: int = 10) -> dict[str, Any]:
    result = {
        "valid": False,
        "protocol": None,
        "cipher": None,
        "grade": "F",
        "message": "Unable to establish TLS connection.",
        "expiry_date": None,
        "days_remaining": None,
    }

    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher() or (None, None, None)
                expiry = cert.get("notAfter")
                expiry_date = _parse_not_after(expiry) if expiry else None

                if expiry_date:
                    expiry_obj = datetime.strptime(expiry_date, "%Y-%m-%d")
                    days_remaining = (expiry_obj - datetime.utcnow()).days
                else:
                    days_remaining = None

                rating = _rate_cipher(cipher[0] or "", protocol or "")
                result.update({
                    "valid": True,
                    "protocol": protocol,
                    "cipher": cipher[0],
                    "grade": rating,
                    "message": "TLS connection established successfully.",
                    "expiry_date": expiry_date,
                    "days_remaining": days_remaining,
                })
    except ssl.SSLError as exc:
        result["message"] = f"TLS handshake failed: {exc}"
    except socket.timeout:
        result["message"] = "TLS connection timed out."
    except Exception as exc:
        result["message"] = str(exc)

    return result

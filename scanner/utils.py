import ipaddress
import re
import socket
from urllib.parse import urlparse

USER_AGENT = "VulnScan Lite/1.0 (+https://example.com)"
PRIVATE_NETWORKS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "fec0::/10",
]
LOCAL_HOSTNAMES = {"localhost", "localhost.localdomain", "local"}
IPV4_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
IPV6_PATTERN = re.compile(r"^[0-9a-fA-F:]+$")


def _to_ip(address: str):
    try:
        return ipaddress.ip_address(address)
    except ValueError:
        return None


def _is_private_network(address: str) -> bool:
    ip = _to_ip(address)
    if not ip:
        return False
    for network in (ipaddress.ip_network(net) for net in PRIVATE_NETWORKS):
        if ip in network:
            return True
    return False


def _resolve_host(hostname: str) -> list[str]:
    addresses = []
    try:
        for item in socket.getaddrinfo(hostname, None):
            address = item[4][0]
            if address not in addresses:
                addresses.append(address)
    except socket.gaierror:
        pass
    return addresses


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty")

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = f"https://{url}"

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs are permitted.")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname.")

    hostname = parsed.hostname.strip().lower()
    if hostname in LOCAL_HOSTNAMES:
        raise ValueError("Local hostnames are not permitted.")

    if IPV4_PATTERN.match(hostname) or IPV6_PATTERN.match(hostname):
        if _is_private_network(hostname):
            raise ValueError("Private or reserved IP addresses are not permitted.")
    else:
        resolved_addresses = _resolve_host(hostname)
        if not resolved_addresses:
            raise ValueError("Hostname could not be resolved.")
        for address in resolved_addresses:
            if _is_private_network(address):
                raise ValueError("Resolved IP address belongs to a private or reserved network.")

    return parsed.geturl()


def get_host_and_port(url: str) -> tuple[str, int]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def build_remediation_note(key: str, message: str) -> dict:
    return {"check": key, "message": message}

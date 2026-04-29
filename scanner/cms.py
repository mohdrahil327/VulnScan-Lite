import re
from bs4 import BeautifulSoup
from typing import Any

CMS_PATTERNS = {
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "shopify": "Shopify",
    "magento": "Magento",
}


def _parse_cms_version(value: str) -> str | None:
    match = re.search(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", value)
    return match.group(1) if match else None


def detect_cms(headers: dict[str, Any], html: str) -> dict[str, Any]:
    normalized = {k.lower(): v for k, v in headers.items()}
    generator = ""
    version = None
    evidence = []
    platform = "Unknown"

    if "x-powered-by" in normalized:
        powered_value = normalized["x-powered-by"]
        evidence.append(f"Header: {powered_value}")
        for key, name in CMS_PATTERNS.items():
            if key in powered_value.lower():
                platform = name
                version = _parse_cms_version(powered_value)
                break

    soup = BeautifulSoup(html, "html.parser")
    generator_tag = soup.find("meta", attrs={"name": "generator"})
    if generator_tag and generator_tag.get("content", ""):
        generator = generator_tag["content"]
        evidence.append(f"Meta generator: {generator}")
        for key, name in CMS_PATTERNS.items():
            if key in generator.lower():
                platform = name
                version = _parse_cms_version(generator)
                break

    if platform == "Unknown" and "wp-" in html.lower():
        platform = "WordPress"
        evidence.append("Found WordPress asset pattern in HTML")

    status = "unknown"
    if platform in ["WordPress", "Drupal", "Joomla"] and version:
        status = "verified"
    elif platform != "Unknown":
        status = "detected"

    return {
        "cms": platform,
        "version": version,
        "status": status,
        "evidence": evidence,
    }

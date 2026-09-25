"""No-network URL/domain structural checks - the fastest, always-run
layer. Each function returns zero or one Signal; run_all() collects
everything into a flat list for the pipeline."""
import ipaddress
from urllib.parse import urlparse

import tldextract

from ..models import Severity, Signal

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "gq", "ml", "cf", "ga",
    "work", "click", "link", "country", "stream", "gdn", "loan",
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}

MAX_REASONABLE_SUBDOMAINS = 3
MAX_REASONABLE_HYPHENS = 4
MAX_REASONABLE_URL_LENGTH = 120


def check_ip_literal_host(host: str) -> "Signal | None":
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None
    return Signal(
        source="url_structure",
        code="ip_literal_host",
        severity=Severity.HIGH,
        message=f"The host is a raw IP address ({host}), not a domain name.",
        evidence={"host": host},
    )


def check_at_symbol(url: str) -> "Signal | None":
    # Everything before an unencoded '@' in the authority is ignored by
    # browsers as userinfo - a classic trick: https://real-bank.com@evil.tld/
    authority = urlparse(url).netloc
    if "@" not in authority:
        return None
    return Signal(
        source="url_structure",
        code="at_symbol_in_authority",
        severity=Severity.HIGH,
        message="The URL uses an '@' in its authority section, a common "
                "trick to disguise the real destination host.",
        evidence={"authority": authority},
    )


def check_subdomain_count(host: str) -> "Signal | None":
    ext = tldextract.extract(host)
    if not ext.subdomain:
        return None
    parts = ext.subdomain.split(".")
    if len(parts) <= MAX_REASONABLE_SUBDOMAINS:
        return None
    return Signal(
        source="url_structure",
        code="excessive_subdomains",
        severity=Severity.MEDIUM,
        message=f"The host has {len(parts)} subdomain levels, more than "
                "typical legitimate sites use.",
        evidence={"subdomain": ext.subdomain},
    )


def check_hyphen_count(host: str) -> "Signal | None":
    count = host.count("-")
    if count <= MAX_REASONABLE_HYPHENS:
        return None
    return Signal(
        source="url_structure",
        code="excessive_hyphens",
        severity=Severity.MEDIUM,
        message=f"The host contains {count} hyphens, often used to pad "
                "out a lookalike domain (e.g. secure-login-account-verify.com).",
        evidence={"host": host},
    )


def check_suspicious_tld(host: str) -> "Signal | None":
    ext = tldextract.extract(host)
    if ext.suffix.lower() not in SUSPICIOUS_TLDS:
        return None
    return Signal(
        source="url_structure",
        code="suspicious_tld",
        severity=Severity.LOW,
        message=f"The domain uses a TLD ('.{ext.suffix}') disproportionately "
                "common in phishing/scam campaigns. Not conclusive on its own.",
        evidence={"tld": ext.suffix},
    )


def check_known_shortener(host: str) -> "Signal | None":
    if host.lower() not in KNOWN_SHORTENERS:
        return None
    return Signal(
        source="url_structure",
        code="url_shortener",
        severity=Severity.LOW,
        message="This is a known URL-shortener domain - the real "
                "destination is hidden until the link is followed.",
        evidence={"host": host},
    )


def check_url_length(url: str) -> "Signal | None":
    if len(url) <= MAX_REASONABLE_URL_LENGTH:
        return None
    return Signal(
        source="url_structure",
        code="unusually_long_url",
        severity=Severity.LOW,
        message=f"The URL is {len(url)} characters long, unusually long "
                "for a normal link.",
        evidence={"length": len(url)},
    )


def check_nonstandard_port(url: str) -> "Signal | None":
    try:
        port = urlparse(url).port
    except ValueError:  # malformed port - the pipeline rejects these up front
        return None
    if port is None or port in (80, 443):
        return None
    return Signal(
        source="url_structure",
        code="nonstandard_port",
        severity=Severity.LOW,
        message=f"The URL specifies a non-standard port ({port}).",
        evidence={"port": port},
    )


def run_all(url: str, host: str) -> "list[Signal]":
    checks = (
        check_ip_literal_host(host),
        check_at_symbol(url),
        check_subdomain_count(host),
        check_hyphen_count(host),
        check_suspicious_tld(host),
        check_known_shortener(host),
        check_url_length(url),
        check_nonstandard_port(url),
    )
    return [s for s in checks if s is not None]

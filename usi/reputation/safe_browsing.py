"""Google Safe Browsing v4 lookup API client - free tier, requires an API
key (console.cloud.google.com, Safe Browsing API enabled). Only the
target URL is sent; no page content. NOTE: written against the
documented v4 threatMatches:find shape; unit-tested against mocked
responses only, not yet verified against a live key - check the response
shape once a key is added."""
import requests

from ..models import Severity, Signal
from .base import ReputationClient

API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
TIMEOUT = 10


class SafeBrowsingClient(ReputationClient):
    name = "safe_browsing"

    def check(self, url: str, host: str) -> "Signal | None":
        if not self.is_configured():
            return None
        body = {
            "client": {"clientId": "url-safety-investigator", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            resp = requests.post(API_URL, params={"key": self.api_key}, json=body, timeout=TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError) as e:
            return self._unavailable_signal(f"lookup failed ({e})")

        matches = data.get("matches") or []
        if not matches:
            return Signal(
                source=self.name, code="safe_browsing_clean", severity=Severity.INFO,
                message="Google Safe Browsing: no known threats matched.",
            )

        threat_types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
        return Signal(
            source=self.name, code="safe_browsing_match", severity=Severity.CRITICAL,
            message=f"Google Safe Browsing flags this URL: {', '.join(threat_types)}.",
            evidence={"threat_types": threat_types},
        )

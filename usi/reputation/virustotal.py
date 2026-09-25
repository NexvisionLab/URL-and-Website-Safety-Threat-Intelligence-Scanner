"""VirusTotal v3 domain-reputation client - free tier (4 req/min),
requires an API key. Only the domain is sent. NOTE: written against the
documented v3 GET /domains/{domain} shape; unit-tested against mocked
responses only, not yet verified against a live key - check the response
shape once a key is added."""
import requests

from ..models import Severity, Signal
from .base import ReputationClient

API_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
TIMEOUT = 10
MALICIOUS_THRESHOLD = 1


class VirusTotalClient(ReputationClient):
    name = "virustotal"

    def check(self, url: str, host: str) -> "Signal | None":
        if not self.is_configured():
            return None
        try:
            resp = requests.get(
                API_URL.format(domain=host),
                headers={"x-apikey": self.api_key},
                timeout=TIMEOUT,
            )
            if resp.status_code == 404:
                return Signal(
                    source=self.name, code="virustotal_unseen", severity=Severity.INFO,
                    message="VirusTotal has no record of this domain.",
                )
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError) as e:
            return self._unavailable_signal(f"lookup failed ({e})")

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious >= MALICIOUS_THRESHOLD:
            return Signal(
                source=self.name, code="virustotal_malicious", severity=Severity.CRITICAL,
                message=f"VirusTotal: {malicious} security vendor(s) flag this domain as malicious.",
                evidence={"malicious": malicious, "suspicious": suspicious},
            )
        if suspicious >= MALICIOUS_THRESHOLD:
            return Signal(
                source=self.name, code="virustotal_suspicious", severity=Severity.MEDIUM,
                message=f"VirusTotal: {suspicious} security vendor(s) flag this domain as suspicious.",
                evidence={"malicious": malicious, "suspicious": suspicious},
            )
        return Signal(
            source=self.name, code="virustotal_clean", severity=Severity.INFO,
            message="VirusTotal: no vendors flag this domain as malicious or suspicious.",
            evidence={"malicious": malicious, "suspicious": suspicious},
        )

"""AbuseIPDB client - free tier, requires an API key. AbuseIPDB rates
IPs, not domains, so this resolves the host to an IP first; DNS
resolution failure is reported, not swallowed as a clean result. NOTE:
written against the documented v2 /check endpoint shape; unit-tested
against mocked responses only, not yet verified against a live key."""
import socket

import requests

from ..models import Severity, Signal
from .base import ReputationClient

API_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = 10
CONFIDENCE_THRESHOLD = 50


class AbuseIPDBClient(ReputationClient):
    name = "abuseipdb"

    def check(self, url: str, host: str) -> "Signal | None":
        if not self.is_configured():
            return None
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            return self._unavailable_signal(f"could not resolve host to an IP ({e})")

        try:
            resp = requests.get(
                API_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self.api_key, "Accept": "application/json"},
                timeout=TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
        except (requests.RequestException, ValueError) as e:
            return self._unavailable_signal(f"lookup failed ({e})")

        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)

        if score >= CONFIDENCE_THRESHOLD:
            return Signal(
                source=self.name, code="abuseipdb_high_confidence", severity=Severity.HIGH,
                message=f"AbuseIPDB: the resolved IP ({ip}) has a {score}% abuse-confidence "
                        f"score from {reports} report(s).",
                evidence={"ip": ip, "score": score, "reports": reports},
            )
        return Signal(
            source=self.name, code="abuseipdb_low_confidence", severity=Severity.INFO,
            message=f"AbuseIPDB: the resolved IP ({ip}) has a low abuse-confidence score ({score}%).",
            evidence={"ip": ip, "score": score, "reports": reports},
        )

"""urlscan.io client - searches EXISTING public scans only (GET
/api/v1/search/), never submits a new scan. Submitting a scan creates a
public record of the target URL and is a side effect this read-only
tool deliberately avoids; searching past scans needs no API key at all,
though a key raises the rate limit. NOTE: written against the
documented search endpoint shape; unit-tested against mocked responses
only, not yet verified live."""
import requests

from ..models import Severity, Signal
from .base import ReputationClient

SEARCH_URL = "https://urlscan.io/api/v1/search/"
TIMEOUT = 10
MALICIOUS_SCORE_THRESHOLD = 50


class UrlscanClient(ReputationClient):
    name = "urlscan"

    def is_configured(self) -> bool:
        # Search works without a key; only gate on the enabled flag.
        return self.enabled

    def check(self, url: str, host: str) -> "Signal | None":
        if not self.is_configured():
            return None
        headers = {"API-Key": self.api_key} if self.api_key else {}
        try:
            resp = requests.get(
                SEARCH_URL, params={"q": f"domain:{host}"}, headers=headers, timeout=TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError) as e:
            return self._unavailable_signal(f"lookup failed ({e})")

        results = data.get("results") or []
        if not results:
            return Signal(
                source=self.name, code="urlscan_no_scans", severity=Severity.INFO,
                message="urlscan.io: no prior public scans found for this domain.",
            )

        malicious_hits = [
            r for r in results
            if (r.get("page", {}).get("verdict") == "malicious")
            or (r.get("verdicts", {}).get("overall", {}).get("score", 0) >= MALICIOUS_SCORE_THRESHOLD)
        ]
        if malicious_hits:
            return Signal(
                source=self.name, code="urlscan_malicious", severity=Severity.CRITICAL,
                message=f"urlscan.io: {len(malicious_hits)} prior scan(s) of this domain were flagged malicious.",
                evidence={"scan_count": len(results), "malicious_count": len(malicious_hits)},
            )
        return Signal(
            source=self.name, code="urlscan_clean", severity=Severity.INFO,
            message=f"urlscan.io: {len(results)} prior scan(s) found, none flagged malicious.",
            evidence={"scan_count": len(results)},
        )

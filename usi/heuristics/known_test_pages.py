"""Recognises pages published specifically as industry security-testing artifacts - AMTSO's "Feature Settings
Check" suite is the only one covered so far. amtso.org is a real, non-malicious domain run by a legitimate
standards body; these specific pages describe themselves as deliberately looking like a threat, purely so a
security product's own live blocking can be tested against it - the same idea as the EICAR antivirus test file.

Found after a real check on https://www.amtso.org/check-desktop-phishing-page came back "Likely Safe" - correctly,
since the page has no credential form, no scam wording and nothing else to flag - while a browser extension
flagged the same URL "Risky / Phishing". That extension's answer comes from a vendor-added test signature, not
from analysing the page, so this scanner's own "Likely Safe" was accurate but gave no sign the page is a
well-known, industry-wide test artifact rather than an ordinary safe page. No network access is needed for this
check, so it always runs, even in --offline mode."""
from urllib.parse import urlparse

from ..models import Severity, Signal

_AMTSO_HOSTS = {"amtso.org", "www.amtso.org"}
# Both of AMTSO's own URL conventions are covered: the current site structure
# (feature-settings-check-phishing-page) and the older path AMTSO kept working
# for products whose blocklists still reference it (check-desktop-phishing-page).
_AMTSO_TEST_PATH_WORDS = ("phishing", "malware", "pua", "drive-by", "cloud-lookup", "cloud_lookup")


def check(host: str, url: str) -> "Signal | None":
    if host.lower() not in _AMTSO_HOSTS:
        return None
    path = urlparse(url).path.lower()
    if "check" not in path or "page" not in path:
        return None
    if not any(word in path for word in _AMTSO_TEST_PATH_WORDS):
        return None
    return Signal(
        source="known_test_pages",
        code="amtso_test_page",
        severity=Severity.INFO,
        message="This is one of AMTSO's own published security-test pages, used industry-wide to check that a "
        "security product's live blocking is switched on and working - the same idea as the EICAR antivirus "
        "test file. It is not a real threat, even if another product's blocklist flags this exact address; "
        "that is the page's intended purpose.",
        evidence={"host": host, "path": path},
    )

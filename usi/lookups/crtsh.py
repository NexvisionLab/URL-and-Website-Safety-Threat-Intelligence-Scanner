"""crt.sh Certificate Transparency log lookup - free, no API key. Used to
corroborate a typosquat finding: a lookalike host that has had a real
TLS certificate issued for it is being actively provisioned as a live
site, not just registered. One request, made only after
heuristics/typosquat.py has already matched the investigated host to a
brand - never a bulk sweep - because crt.sh is a free community service
other people also depend on.

This deliberately checks the INVESTIGATED host, not other variants of
the brand's domain: reporting on an unrelated lookalike that merely
exists (and may be innocent) would attribute someone else's certificate
to the URL being judged."""
import requests

from ..models import Severity, Signal

CRTSH_URL = "https://crt.sh/"
CRTSH_TIMEOUT = 15
USER_AGENT = "url-safety-investigator/0.1 (local research tool)"


def has_certificate(domain: str) -> "bool | None":
    """Returns True/False, or None if the lookup itself failed (network
    error, crt.sh unavailable) - callers must not treat None as False."""
    try:
        resp = requests.get(
            CRTSH_URL,
            params={"q": domain, "output": "json"},
            timeout=CRTSH_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        if resp.status_code != 200:
            return None
        data = resp.json() if resp.text.strip() else []
        return len(data) > 0
    except (requests.RequestException, ValueError):
        return None


def check_lookalike_host(host: str) -> "list[Signal]":
    """Corroborates a typosquat match on `host` itself. MEDIUM, not
    higher: the typosquat finding is already HIGH on its own, and a
    certificate existing is common to legitimate sites too - this only
    adds "it's provisioned", it doesn't prove intent."""
    if has_certificate(host) is not True:
        return []
    return [Signal(
        source="crtsh", code="lookalike_has_cert", severity=Severity.MEDIUM,
        message=f"Certificate Transparency logs show a real TLS certificate has been "
                f"issued for the lookalike domain '{host}' - it is being actively "
                "provisioned as a live site, not just registered.",
        evidence={"domain": host},
    )]

"""WHOIS lookup: domain age, registrar, privacy-protection flag. WHOIS
is flaky per-TLD and doesn't exist for .onion, so every failure mode is
caught and turned into a "whois_unavailable" INFO signal - never a
crash, and never silently treated as a clean/safe result.

When WHOIS gives no registration data (the case for .sg and several
other ccTLDs), the same facts are read from RDAP instead (rdap.py) and
reported under the same signal codes, marked "via": "rdap"."""
from datetime import datetime

import whois

from ..models import Severity, Signal
from . import rdap

YOUNG_DOMAIN_DAYS = 30
_PRIVACY_MARKERS = ("privacy", "redacted", "whoisguard", "proxy", "protected")

# A registration period within this many days of exactly one year (the
# minimum/cheapest period a registrar offers) is a common, weak,
# throwaway-domain signal - plenty of legitimate small sites also just
# register for one year to save money, so this stays a tolerance band
# around 365 days rather than an exact-match, and is deliberately kept
# at INFO severity (context, not a verdict-mover) rather than escalated.
SHORT_REGISTRATION_TOLERANCE_DAYS = 5


def _first(value):
    """python-whois sometimes returns a list for a field (multiple WHOIS
    servers disagreeing) - take the earliest/first sensible value."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def lookup(host: str, skip: bool = False) -> "list[Signal]":
    if skip:
        return [Signal(
            source="whois", code="whois_unavailable", severity=Severity.INFO,
            message="WHOIS not applicable for this host (.onion or skipped).",
        )]

    try:
        w = whois.whois(host)
    except Exception as e:
        via_rdap = _from_rdap(host)
        if via_rdap is not None:
            return via_rdap
        # python-whois sometimes raises with the *entire* raw WHOIS response
        # (including a server's full terms-of-use boilerplate) as the
        # exception text - truncate hard so one failed lookup doesn't dump
        # paragraphs of legalese into the report.
        reason = str(e).strip().splitlines()[0][:200] if str(e).strip() else type(e).__name__
        return [Signal(
            source="whois", code="whois_unavailable", severity=Severity.INFO,
            message=f"WHOIS lookup failed: {reason}",
        )]

    creation_date = _first(getattr(w, "creation_date", None))
    expiration_date = _first(getattr(w, "expiration_date", None))
    registrar = _first(getattr(w, "registrar", None))
    # python-whois's .text is usually a plain string (the raw WHOIS
    # response), sometimes a list. Joining a string with spaces would walk
    # it character by character ("REDACTED" -> "R E D A C T E D") and
    # break the substring checks below, so only join real lists.
    _raw_text_attr = getattr(w, "text", None)
    if isinstance(_raw_text_attr, list):
        raw_text = " ".join(str(v) for v in _raw_text_attr).lower()
    elif _raw_text_attr:
        raw_text = str(_raw_text_attr).lower()
    else:
        raw_text = ""

    if creation_date is None and registrar is None:
        via_rdap = _from_rdap(host)
        if via_rdap is not None:
            return via_rdap
        return [Signal(
            source="whois", code="whois_unavailable", severity=Severity.INFO,
            message="WHOIS returned no usable registration data for this domain.",
        )]

    return _registration_signals(creation_date, expiration_date, registrar, raw_text)


def _from_rdap(host: str) -> "list[Signal] | None":
    """The RDAP fallback. None when RDAP has nothing either, so the caller
    keeps reporting WHOIS as unavailable."""
    try:
        data = rdap.registration(host)
    except Exception:  # noqa: BLE001 - a fallback must never turn a lookup failure into a crash
        return None
    if not data:
        return None
    signals = _registration_signals(data["created"], data["expires"], data["registrar"], "", via="rdap")
    return signals or None


def _registration_signals(creation_date, expiration_date, registrar, raw_text: str,
                          via: str = "whois") -> "list[Signal]":
    signals = []

    if isinstance(creation_date, datetime):
        now = datetime.now(creation_date.tzinfo) if creation_date.tzinfo else datetime.now()
        age_days = (now - creation_date).days
        if age_days < YOUNG_DOMAIN_DAYS:
            signals.append(Signal(
                source="whois", code="young_domain", severity=Severity.MEDIUM,
                message=f"This domain was registered only {age_days} day(s) ago - "
                        "freshly-registered domains are disproportionately used in scams.",
                evidence={"creation_date": creation_date.isoformat(), "age_days": age_days, "via": via},
            ))
        else:
            signals.append(Signal(
                source="whois", code="domain_age", severity=Severity.INFO,
                message=f"Domain registered {age_days} day(s) ago.",
                evidence={"creation_date": creation_date.isoformat(), "age_days": age_days, "via": via},
            ))

    if isinstance(creation_date, datetime) and isinstance(expiration_date, datetime):
        # Normalize both to naive or both to aware before subtracting -
        # WHOIS servers are inconsistent about including tzinfo.
        c_date = creation_date.replace(tzinfo=None) if creation_date.tzinfo else creation_date
        e_date = expiration_date.replace(tzinfo=None) if expiration_date.tzinfo else expiration_date
        registration_days = (e_date - c_date).days
        if abs(registration_days - 365) <= SHORT_REGISTRATION_TOLERANCE_DAYS:
            signals.append(Signal(
                source="whois", code="short_registration_period", severity=Severity.INFO,
                message="This domain was registered for only one year - common for both "
                        "throwaway/disposable domains and legitimate small sites saving "
                        "on registration cost. Not conclusive on its own.",
                evidence={"registration_days": registration_days},
            ))

    if any(marker in raw_text for marker in _PRIVACY_MARKERS):
        signals.append(Signal(
            source="whois", code="privacy_protected", severity=Severity.INFO,
            message="Registrant details are privacy-protected. Common for both "
                    "legitimate and malicious sites - not conclusive on its own.",
        ))

    if registrar:
        signals.append(Signal(
            source="whois", code="registrar", severity=Severity.INFO,
            message=f"Registrar: {registrar}",
            evidence={"registrar": registrar},
        ))

    return signals

"""Verdict aggregation: an explicit, priority-ordered rule evaluation -
never a summed opaque score (first-match-in-priority-order wins),
extended with a weak-signal co-occurrence tier. Every VerdictReport carries the full
signal list so the report can show exactly *why* a verdict was reached."""
from ..models import Severity, Signal, VerdictReport

# A layer that ATTEMPTED a check but hit an error (network failure, WHOIS
# timeout, etc). Every reputation client's "unavailable" signal follows
# the f"{name}_unavailable" naming convention (see reputation/base.py).
def _is_failure_code(code: str) -> bool:
    return code == "fetch_failed" or code.endswith("_unavailable")

# A layer the USER deliberately chose not to run (--no-fetch, --offline).
# Not a failure - must never contribute to an "Unknown" verdict, since the
# absence of that data was requested, not encountered.
_SKIP_CODES = {"fetch_skipped"}

MEDIUM_COOCCURRENCE_THRESHOLD = 2


def rate(signals: "list[Signal]") -> VerdictReport:
    real_signals = [
        s for s in signals
        if not _is_failure_code(s.code) and s.code not in _SKIP_CODES
    ]

    critical = [s for s in real_signals if s.severity == Severity.CRITICAL]
    if critical:
        return VerdictReport(verdict="Likely Malicious", signals=signals)

    high = [s for s in real_signals if s.severity == Severity.HIGH]
    if high:
        return VerdictReport(verdict="Suspicious", signals=signals)

    medium = [s for s in real_signals if s.severity == Severity.MEDIUM]
    if len(medium) >= MEDIUM_COOCCURRENCE_THRESHOLD:
        return VerdictReport(verdict="Suspicious", signals=signals)

    # "Unknown": at least one layer was actually attempted and failed, and
    # NOTHING else - not even a clean INFO signal - was gathered from any
    # source. Never fires just because the user chose to skip a layer, and
    # never fires on a clean run that simply found nothing to report.
    any_failure_attempted = any(_is_failure_code(s.code) for s in signals)
    if any_failure_attempted and not real_signals:
        return VerdictReport(verdict="Unknown", signals=signals)

    return VerdictReport(verdict="Likely Safe", signals=signals)

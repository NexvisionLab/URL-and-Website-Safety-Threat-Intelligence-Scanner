"""Redirect-chain analysis. `requests` (via fetcher.py) already follows
the full chain internally; fetcher.py keeps every intermediate hop
(shorteners, tracking redirectors, unrelated domains) so it can be
analyzed here rather than only the final URL. Excessive redirect depth
is itself a known evasion/cloaking technique; a chain crossing through a shortener or landing somewhere
entirely unrelated to what was requested is useful investigator context
even when nothing else fires.

Deliberately calibrated toward INFO/LOW severities for the common case:
one or two redirects (http->https, bare domain->www, a legitimate
tracking link) are completely normal and must not read as suspicious on
their own. Only genuinely excessive chains escalate."""
from ..models import RedirectHop, Severity, Signal
from .url_structure import KNOWN_SHORTENERS, SUSPICIOUS_TLDS

EXCESSIVE_HOP_THRESHOLD = 4


def _registrable_ish(host: str) -> str:
    """Cheap same-site check without pulling in tldextract here - good
    enough to tell 'www.example.com' from 'example.com' (same site) vs
    a genuinely different domain, which is all this needs."""
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def analyze(requested_host: str, final_host: str, chain: "list[RedirectHop]") -> "list[Signal]":
    if not chain:
        return []

    signals = []
    hop_hosts = [h.host for h in chain]

    if len(chain) > EXCESSIVE_HOP_THRESHOLD:
        signals.append(Signal(
            source="redirect_chain", code="excessive_redirect_hops", severity=Severity.MEDIUM,
            message=f"The request went through {len(chain)} redirects before landing on the "
                    "final page - more than typical legitimate flows use, and a technique "
                    "sometimes used to evade automated scanners.",
            evidence={"hop_count": len(chain), "hosts": hop_hosts},
        ))

    shortener_hops = [h for h in hop_hosts if h.lower() in KNOWN_SHORTENERS]
    if shortener_hops:
        signals.append(Signal(
            source="redirect_chain", code="redirect_through_shortener", severity=Severity.LOW,
            message=f"The redirect chain passes through a known URL shortener "
                    f"({', '.join(sorted(set(shortener_hops)))}), which can hide the true "
                    "path a link takes before its final destination.",
            evidence={"shortener_hosts": shortener_hops},
        ))

    suspicious_tld_hops = [
        h for h in hop_hosts if "." in h and h.lower().rsplit(".", 1)[-1] in SUSPICIOUS_TLDS
    ]
    if suspicious_tld_hops:
        signals.append(Signal(
            source="redirect_chain", code="redirect_through_suspicious_tld", severity=Severity.LOW,
            message="The redirect chain passes through a domain on a TLD disproportionately "
                    "common in phishing/scam campaigns.",
            evidence={"hosts": suspicious_tld_hops},
        ))

    if _registrable_ish(requested_host) != _registrable_ish(final_host):
        signals.append(Signal(
            source="redirect_chain", code="landed_on_different_domain", severity=Severity.INFO,
            message=f"The URL redirected to a different domain ('{final_host}') than the one "
                    f"requested ('{requested_host}').",
            evidence={"requested_host": requested_host, "final_host": final_host},
        ))
    else:
        signals.append(Signal(
            source="redirect_chain", code="redirect_chain_summary", severity=Severity.INFO,
            message=f"Followed {len(chain)} redirect(s) to reach the final page.",
            evidence={"hop_count": len(chain), "hosts": hop_hosts},
        ))

    return signals

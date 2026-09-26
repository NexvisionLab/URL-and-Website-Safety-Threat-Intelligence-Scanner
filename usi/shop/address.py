"""Evidence from the web address alone - for shops whose pages we can't
examine (bot checks, script-only pages) as much as for those we can.

- Random-letter names ("bnbsjbir.shop"): bulk-registered fake shops often
  use generated names. Scored as a likelihood ratio between letter pairs
  of real website names (data/name_bigrams.json, built from the Tranco
  list) and uniformly random letters. Six or seven random letters carry
  little evidence, so this is only ever a minor sign on its own.
- First certificate: Certificate Transparency logs show when the address
  first got a TLS certificate - an age for domains whose registry
  publishes none (.de, .at), and, on an old domain, the moment a
  long-registered address first became a website (re-registered expired
  domains, which BogusBazaar favoured, look like this).
- Known fake-shop hosting: the server addresses Malwarebytes published
  for a network of 20,000+ fake shops (data/fake_shop_hosting.json).
  Exact addresses only: the surrounding ranges belong to a large hosting
  provider with plenty of legitimate customers."""
import json
import math
import re
import socket
from datetime import datetime, timezone
from pathlib import Path

import requests
import tldextract

from ..models import Severity, Signal
from ..lookups.rdap import registrable_domain

AGE_SOURCE = "shop_age"
COPY_SOURCE = "shop_copy"
DATA = Path(__file__).resolve().parent.parent.parent / "data"

# Log-likelihood ratio (bits) below which a name reads as random letters. Measured 2026-09-26 on
# single-word names of 6-14 letters from Tranco ranks 500,001-900,000: 0.5% fall below it, and the ones
# that do are themselves mostly generated junk names; every genuine shop name in data/shop_eval.csv
# scores above -3.
RANDOM_NAME_LLR = -8.0
NEW_CERT_DAYS = 90
CRTSH_URL = "https://crt.sh/"
# crt.sh is a free community service and often slow or overloaded (measured 2026-09-26: 6-16 s for small
# shops, 502s, timeouts for large sites with thousands of certificates). The lookup is best-effort: capped so
# it never holds up a check, and a failure is only noted, never counted against the shop.
CRTSH_TIMEOUT = 10
USER_AGENT = "url-safety-investigator/0.1 (local research tool)"

_extract = tldextract.TLDExtract(suffix_list_urls=())
_model = None


def _load_model():
    global _model
    if _model is None:
        m = json.loads((DATA / "name_bigrams.json").read_text(encoding="utf-8"))
        alphabet, counts = m["alphabet"], m["counts"]
        lp = {}
        for i, a in enumerate(alphabet):
            total = sum(counts[i])
            for j, b in enumerate(alphabet):
                lp[a, b] = math.log2((counts[i][j] + 0.5) / (total + 0.5 * len(alphabet)))
        _model = lp
    return _model


def name_llr(token: str) -> float:
    """Bits of evidence that `token` is a real-looking name rather than random letters (negative: random)."""
    lp = _load_model()
    s = "^" + token + "$"
    real = sum(lp[a, b] for a, b in zip(s, s[1:]))
    random_letters = len(token) * math.log2(1 / 26) + math.log2(1 / 27)
    return real - random_letters


def random_name_signal(host: str) -> "Signal | None":
    label = _extract(host.lower()).domain
    if not re.fullmatch(r"[a-z]{6,14}", label or ""):
        return None
    score = name_llr(label)
    if score >= RANDOM_NAME_LLR:
        return None
    return Signal(
        source=COPY_SOURCE, code="shop_random_name", severity=Severity.LOW,
        message=(f"The name '{label}' looks like random letters rather than a word or brand. Networks of fake shops "
                 "register generated names like this in bulk; on its own it proves nothing."),
        evidence={"label": label, "llr_bits": round(score, 1)},
    )


def first_certificate(domain: str) -> "datetime | None | bool":
    """Earliest certificate for the domain in Certificate Transparency logs (crt.sh): a datetime, False
    when there is none, or None when crt.sh couldn't be reached. crt.sh is a free community service:
    one request per shop check, never a sweep."""
    try:
        resp = requests.get(CRTSH_URL, params={"q": domain, "output": "json"}, timeout=CRTSH_TIMEOUT,
                            headers={"User-Agent": USER_AGENT})
        if resp.status_code != 200:
            return None
        rows = resp.json() if resp.text.strip() else []
    except (requests.RequestException, ValueError):
        return None
    dates = []
    for row in rows if isinstance(rows, list) else []:
        try:
            dates.append(datetime.fromisoformat(str(row.get("not_before")).replace("Z", "")).replace(tzinfo=timezone.utc))
        except (TypeError, ValueError):
            continue
    return min(dates) if dates else False


def certificate_signals(first, domain_age_days: "int | None", now: "datetime | None" = None) -> "list[Signal]":
    if first is None:
        return [Signal(source=AGE_SOURCE, code="shop_cert_history_unavailable", severity=Severity.INFO,
                       message="The certificate logs couldn't be reached to see when this site first went online.")]
    if first is False:
        return [Signal(source=AGE_SOURCE, code="shop_cert_none", severity=Severity.INFO,
                       message="No certificate has ever been logged for this address.")]
    days = max(0, ((now or datetime.now(timezone.utc)) - first).days)
    evidence = {"first_certificate": first.date().isoformat(), "days": days}
    if days >= NEW_CERT_DAYS:
        return [Signal(source=AGE_SOURCE, code="shop_cert_age", severity=Severity.INFO,
                       message=f"The site's first certificate was issued {days} days ago.", evidence=evidence)]
    if domain_age_days is not None and domain_age_days >= 730:
        return [Signal(
            source=AGE_SOURCE, code="shop_old_domain_new_site", severity=Severity.LOW,
            message=(f"The address has been registered for {domain_age_days // 365} years but only got its first "
                     f"certificate {days} days ago - it became a website only recently. Fake-shop networks buy "
                     "expired addresses with a history for exactly this reason."),
            evidence={**evidence, "domain_age_days": domain_age_days},
        )]
    return [Signal(
        source=AGE_SOURCE, code="shop_cert_new", severity=Severity.MEDIUM,
        message=f"The site got its first certificate only {days} day(s) ago, so it has been online for a very short time.",
        evidence=evidence,
    )]


def _hosting_list() -> dict:
    return json.loads((DATA / "fake_shop_hosting.json").read_text(encoding="utf-8"))


def resolve(host: str) -> "list[str]":
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
    except (socket.gaierror, UnicodeError, OSError):
        return []


def hosting_signals(addresses: "list[str]") -> "list[Signal]":
    data = _hosting_list()
    for entry in data["sources"]:
        hits = sorted(set(addresses) & set(entry["addresses"]))
        if hits:
            return [Signal(
                source=COPY_SOURCE, code="shop_known_fake_hosting", severity=Severity.MEDIUM,
                message=(f"The shop runs on a server ({hits[0]}) that {entry['publisher']} reported in "
                         f"{entry['published']} as hosting a network of fake shops."),
                evidence={"addresses": hits, "report": entry["url"], "published": entry["published"]},
            )]
    return []


def check(host: str, domain_age_days: "int | None") -> "tuple[list[Signal], dict]":
    domain = registrable_domain(host) or host
    signals: "list[Signal]" = []
    name = random_name_signal(host)
    if name:
        signals.append(name)
    first = first_certificate(domain)
    signals += certificate_signals(first, domain_age_days)
    addresses = resolve(host)
    signals += hosting_signals(addresses)
    facts = {"first_certificate": first.date().isoformat() if isinstance(first, datetime) else None,
             "addresses": addresses[:4]}
    return signals, facts

"""Typosquat/combosquat detection: given the investigated host, check
whether it is a lookalike of any brand in data/brands.json. Generates a
bounded set of candidate variants per brand (character omission,
adjacent-transposition, digit-homoglyph substitution, repetition,
hyphenation, combosquat keywords, TLD-swap) and checks the investigated
host against that set - deliberately not the full dnstwist technique
set (bitsquatting, full-unicode homoglyphs, keyboard-adjacency), which
covers the overwhelming majority of real-world squats without a heavy
extra dependency. No network calls here; crt.sh corroboration for a
match happens separately in lookups/crtsh.py."""
import json
import re
from pathlib import Path

from ..models import Severity, Signal

MAX_CANDIDATES_PER_BRAND = 150

_HOMOGLYPH_SUBS = {
    "o": "0", "l": "1", "i": "1", "e": "3",
    "a": "4", "s": "5", "g": "9", "b": "6", "t": "7",
}
# Digits commonly substituted for letters ("1" is handled separately: it
# stands in for both "l" and "i").
_LOOKALIKE_DIGITS = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "6": "b", "7": "t", "9": "g"})
_COMBOSQUAT_KEYWORDS = (
    # English
    "login", "secure", "account", "support", "verify",
    "update", "service", "help", "portal", "id",
    # India-specific: "KYC" (Know Your Customer) verification is a
    # very common lure in India's UPI banking-fraud campaigns - kept as
    # its own keyword rather than folded into a generic "verify" bucket.
    "kyc",
    # Spanish (ASCII-transliterated, matching how these actually appear
    # in real registered domain names - accents are stripped)
    "iniciar-sesion", "cuenta", "verificar", "soporte", "seguro",
    # Portuguese
    "entrar", "conta", "suporte", "seguranca",
    # French
    "connexion", "compte", "verifier", "securise",
    # German
    "anmelden", "konto", "verifizieren", "sicherheit",
)
_ALT_TLDS = (
    "com", "net", "org", "info", "xyz", "top", "online", "site", "co", "io",
)

DEFAULT_BRANDS_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "brands.json"


def load_brands(path: "Path | None" = None) -> "list[dict]":
    path = path or DEFAULT_BRANDS_PATH
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["brands"]


def _split_domain(domain: str) -> "tuple[str, str] | tuple[None, None]":
    parts = domain.lower().strip().rstrip(".").split(".")
    if len(parts) < 2:
        return None, None
    return ".".join(parts[:-1]), parts[-1]


def generate_candidates(domain: str, max_candidates: int = MAX_CANDIDATES_PER_BRAND) -> "set[str]":
    name, tld = _split_domain(domain)
    if name is None:
        return set()

    candidates: "set[str]" = set()

    # 1. Character omission (drop one char at a time)
    for i in range(len(name)):
        candidates.add(name[:i] + name[i + 1:] + "." + tld)

    # 2. Adjacent transposition
    for i in range(len(name) - 1):
        swapped = name[:i] + name[i + 1] + name[i] + name[i + 2:]
        candidates.add(swapped + "." + tld)

    # 3. Character repetition (double one char at a time)
    for i in range(len(name)):
        candidates.add(name[:i] + name[i] * 2 + name[i + 1:] + "." + tld)

    # 4. Digit-homoglyph substitution (one substitution at a time)
    for i, ch in enumerate(name):
        sub = _HOMOGLYPH_SUBS.get(ch)
        if sub:
            candidates.add(name[:i] + sub + name[i + 1:] + "." + tld)

    # 5. Hyphenation (insert a hyphen between each pair of chars)
    for i in range(1, len(name)):
        candidates.add(name[:i] + "-" + name[i:] + "." + tld)

    # 6. Combosquat keywords (brand-keyword and keyword-brand)
    for kw in _COMBOSQUAT_KEYWORDS:
        candidates.add(f"{name}-{kw}." + tld)
        candidates.add(f"{kw}-{name}." + tld)

    # 7. TLD swap
    for alt in _ALT_TLDS:
        if alt != tld:
            candidates.add(name + "." + alt)

    candidates.discard(domain.lower())
    if len(candidates) > max_candidates:
        candidates = set(sorted(candidates)[:max_candidates])
    return candidates


def _is_known_brand_host(host_l: str, brands: "list[dict]") -> bool:
    """True if the host is (a subdomain of) ANY listed brand's real domain.
    Checked across all brands up front - skipping only the current brand's
    own domains let a shorter brand ("Meta") match another brand's real
    site (metamask.io) as a lookalike."""
    return any(
        host_l == d or host_l.endswith("." + d)
        for brand in brands for d in (x.lower() for x in brand["domains"])
    )


def find_typosquat_match(host: str, brands: "list[dict]") -> "Signal | None":
    host_l = host.lower()
    if _is_known_brand_host(host_l, brands):
        return None
    for brand in brands:
        name = brand["name"]
        for real_domain in brand["domains"]:
            if host_l == real_domain.lower():
                return None  # it *is* the real domain, nothing to flag
        for real_domain in brand["domains"]:
            if host_l in generate_candidates(real_domain):
                return Signal(
                    source="typosquat",
                    code="typosquat_match",
                    severity=Severity.HIGH,
                    message=(
                        f"'{host}' closely resembles '{real_domain}' ({name}) - "
                        "a common typosquat/combosquat pattern of a well-known brand."
                    ),
                    evidence={"host": host, "brand": name, "real_domain": real_domain},
                )
    return None


def find_combosquat_keyword_match(host: str, brands: "list[dict]") -> "Signal | None":
    """Catches combosquats the fixed permutation list wouldn't generate,
    e.g. 'paypal-account-support-team.net' - substring match of the
    brand's bare name in the host, on a domain that isn't the brand's
    own (or a legitimate subdomain of it).

    Collects every brand whose name substring-matches, then reports the
    LONGEST (most specific) match rather than the first one found in
    brands.json's list order. Without this, a short/generic brand name
    that happens to be a substring of a longer, more specific brand
    (e.g. "Meta" inside "MetaMask") would shadow the correct
    attribution just by sitting earlier in the file:
    'metamask-connect.vercel.app' must be attributed to MetaMask, not to
    Meta, Facebook's parent."""
    host_l = host.lower()
    if _is_known_brand_host(host_l, brands):
        return None
    host_stripped = host_l.replace("-", "").replace(".", "")
    # Look-alike characters are undone before matching so "paypa1-login"
    # can't slip past a substring check for "paypal" - the same digit-for-
    # letter tricks generate_candidates() already knows about.
    haystacks = _lookalike_variants(host_stripped)
    # A brand name alone is weak (plenty of unrelated sites contain one);
    # brand name PLUS a credential/verification word as its own label
    # ("paypal-login", "secure-chase") is the classic phishing shape.
    tokens = set(re.split(r"[.\-]", host_l))
    keywords = sorted(
        {kw for kw in _COMBOSQUAT_KEYWORDS if ("-" in kw and kw in host_l) or kw in tokens}
    )
    matches = []
    for brand in brands:
        name_l = brand["name"].lower().replace(" ", "").replace("/", "")
        if len(name_l) < 4:
            # Too short to substring-match safely (DHL/UPS/IRS are among the
            # most-impersonated brands, but "ups" is inside plenty of
            # words): require it as a whole label AND a phishing keyword.
            if name_l in tokens and keywords:
                matches.append((name_l, brand["name"]))
            continue
        real_domains = [d.lower() for d in brand["domains"]]
        if host_l in real_domains:
            continue
        if any(host_l.endswith("." + d) for d in real_domains):
            continue  # legitimate subdomain
        if any(name_l in h for h in haystacks):
            matches.append((name_l, brand["name"]))

    if not matches:
        return None

    matches.sort(key=lambda m: -len(m[0]))
    _, brand_name = matches[0]
    return Signal(
        source="typosquat",
        code="combosquat_keyword_match",
        severity=Severity.HIGH if keywords else Severity.MEDIUM,
        message=(
            f"'{host}' contains the brand name '{brand_name}'"
            + (f" alongside {', '.join(repr(k) for k in keywords)}" if keywords else "")
            + " but is not one of its known domains - a common combosquat pattern."
        ),
        evidence={"host": host, "brand": brand_name, "keywords": keywords},
    )


def _lookalike_variants(host_stripped: str) -> "set[str]":
    """The host as written plus digit/letter look-alike-normalized forms."""
    base = host_stripped.translate(_LOOKALIKE_DIGITS)
    return {host_stripped, base.replace("1", "l"), base.replace("1", "i"), base.replace("rn", "m")}


def run_all(host: str, brands: "list[dict] | None" = None) -> "list[Signal]":
    brands = brands if brands is not None else load_brands()
    match = find_typosquat_match(host, brands)
    if match:
        return [match]
    combosquat = find_combosquat_keyword_match(host, brands)
    return [combosquat] if combosquat else []

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


# Platforms where a page's name is an account name that only its owner can hold (github.com/microsoft owns microsoft.github.io), so
# a page named exactly like a brand there is the brand's own. Not true of Weebly, Wix, Blogspot and the like, where anyone can claim
# paypal.weebly.com first, so those stay covered by the lookalike checks.
ORG_NAMESPACE_SUFFIXES = ("github.io", "gitlab.io")


def is_official_org_page(host_l: str, brands: "list[dict]") -> bool:
    """True for <brand>.github.io / <brand>.gitlab.io where the single label is exactly a listed brand's name. Only the brand's
    own name counts (not its aliases, and not 'microsoft-login'), and a nested host (a.b.github.io) never does. The content
    checks (a login form imitating a brand) still run on such a page."""
    for suffix in ORG_NAMESPACE_SUFFIXES:
        if host_l.endswith("." + suffix):
            label = host_l[: -(len(suffix) + 1)]
            return "." not in label and any(label == _norm(brand["name"]) for brand in brands)
    return False


def _is_known_brand_host(host_l: str, brands: "list[dict]") -> bool:
    """True if the host is (a subdomain of) ANY listed brand's real domain, or the brand's own account page on GitHub or GitLab
    Pages. Checked across all brands up front - skipping only the current brand's
    own domains let a shorter brand ("Meta") match another brand's real
    site (metamask.io) as a lookalike."""
    return is_official_org_page(host_l, brands) or any(
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
                        "a common typosquat/combosquat pattern of a well-known brand. "
                        f"The real {name} website is {real_domain}."
                    ),
                    evidence={"host": host, "brand": name, "real_domain": real_domain,
                              "real_domains": brand["domains"][:3]},
                )
    return None


# Free hosting and site-builder platforms: anyone can register a subdomain there, so a well-known brand's name inside
# one says nothing about who runs the page. Seen in 2026-09 phishing feeds: netflix-71f05.firebaseapp.com,
# connexioncompteoutlook.weebly.com, not-start-eng-trezr.pages.dev, verifiedbadge-celestine.vercel.app.
FREE_HOSTING_SUFFIXES = (
    "weebly.com", "weeblysite.com", "wixsite.com", "blogspot.com", "github.io", "gitbook.io", "netlify.app", "vercel.app",
    "pages.dev", "workers.dev", "firebaseapp.com", "web.app", "framer.website", "framer.app", "framer.ai", "framer.media",
    "replit.app", "replit.dev", "herokuapp.com", "glitch.me", "webadorsite.com", "square.site", "craftum.io", "freepage.cc",
    "previewship.net", "railway.app", "azurewebsites.net", "cloudapp.azure.com", "onrender.com", "fly.dev", "surge.sh",
    "000webhostapp.com", "godaddysites.com", "strikingly.com", "carrd.co", "notion.site", "webflow.io", "bubbleapps.io",
    "wordpress.com", "tumblr.com", "jimdofree.com", "site123.me", "mystrikingly.com",
)
# Words that make a brand name on a free host look like a lure. Long ones count anywhere in the name; short ones (which sit
# inside ordinary words: "hidden", "payroll") only when they stand alone between hyphens or dots.
_LURE_SUBSTRINGS = (
    "connexion", "compte", "login", "signin", "verify", "verif", "secure", "support", "account", "update", "confirm", "wallet",
    "official", "claim", "reward", "recover", "unlock", "billing", "service", "cuenta", "iniciar", "anmelden", "konto",
    "authenticat", "suspend", "security",
)
_LURE_TOKENS = ("id", "web", "pay", "free", "gift", "help", "kyc", "offer", "prize", "app", "sso", "auth", "cs")


def _free_host_suffix(host_l: str) -> "str | None":
    for suffix in FREE_HOSTING_SUFFIXES:
        if host_l.endswith("." + suffix):
            return suffix
    return None


def _norm(name: str) -> str:
    """A brand name as it would appear in a hostname: no spaces, slashes or dots ('Booking.com' -> 'bookingcom')."""
    return name.lower().replace(" ", "").replace("/", "").replace(".", "")


def _name_variants(brand: dict) -> "list[tuple[str, str]]":
    """(normalised name, the text to show) for the brand's name, its aliases, and - for a dotted name like 'Booking.com' -
    the part before the dot ('booking'), which phishing hosts use on its own ('secure-checkout-booking.com')."""
    out = []
    for raw in [brand["name"]] + list(brand.get("aliases", [])):
        out.append((_norm(raw), raw))
        if "." in raw:
            stem = _norm(raw.split(".", 1)[0])
            if len(stem) >= 5:
                out.append((stem, raw.split(".", 1)[0]))
    return out


def _real_domain_for(brand: dict, shown: str) -> str:
    """The real domain to point a visitor at: the one starting with the matched name if there is one (alias 'instagram' -> instagram.com)."""
    key = _norm(shown)
    for d in brand["domains"]:
        if d.lower().startswith(key):
            return d
    return brand["domains"][0]


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
    Meta, Facebook's parent.

    A brand entry may carry "aliases" (other names the brand is known by: Microsoft -> outlook), and a name that
    contains a dot ('Booking.com') is also matched by its part before the dot. On a free-hosting subdomain
    (FREE_HOSTING_SUFFIXES) a brand name that stands as its own word, together with digits or a lure word, is HIGH."""
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
        real_domains = [d.lower() for d in brand["domains"]]
        if host_l in real_domains:
            continue
        if any(host_l.endswith("." + d) for d in real_domains):
            continue  # legitimate subdomain
        for name_l, shown in _name_variants(brand):
            if len(name_l) < 4:
                # Too short to substring-match safely (DHL/UPS/IRS are among the
                # most-impersonated brands, but "ups" is inside plenty of
                # words): require it as a whole label AND a phishing keyword.
                if name_l in tokens and keywords:
                    matches.append((name_l, shown, brand))
                continue
            if any(name_l in h for h in haystacks):
                matches.append((name_l, shown, brand))

    if not matches:
        return None

    matches.sort(key=lambda m: -len(m[0]))
    name_l, shown, matched_brand = matches[0]
    brand_name = matched_brand["name"]
    real_domain = _real_domain_for(matched_brand, shown)
    real_domains = [real_domain] + [d for d in matched_brand["domains"] if d != real_domain][:2]
    # any of the brand's names standing as its own word counts ('booking' for 'Booking.com'), not only the longest variant
    whole_label = any(v in tokens for v, _ in _name_variants(matched_brand))

    free_suffix = _free_host_suffix(host_l)
    lured = False
    if free_suffix:
        sub = host_l[: -(len(free_suffix) + 1)]
        digits = sum(c.isdigit() for c in sub) >= 2
        lure_word = any(w in sub for w in _LURE_SUBSTRINGS) or any(w in set(re.split(r"[.\-]", sub)) for w in _LURE_TOKENS)
        # a brand's own official page on such a platform ('microsoft.github.io') is the bare name: not enough on its own
        lured = (whole_label or len(name_l) >= 6) and sub != name_l and (digits or lure_word)

    label = shown if _norm(shown) != _norm(brand_name) else brand_name
    return Signal(
        source="typosquat",
        code="combosquat_keyword_match",
        severity=Severity.HIGH if (keywords or lured) else Severity.MEDIUM,
        message=(
            f"'{host}' contains the brand name '{label}'"
            + (f" alongside {', '.join(repr(k) for k in keywords)}" if keywords else "")
            + " but is not one of its known domains - a common combosquat pattern. "
            + (f"It is a page on a free hosting service ({free_suffix}), where anyone can pick a name. " if lured else "")
            + f"The real {brand_name} website is {real_domain}."
        ),
        evidence={"host": host, "brand": brand_name, "keywords": keywords, "real_domains": real_domains,
                  # the brand's name stands as its own word in the host ("xzy-singpost.com"), not just
                  # a substring of a longer word ("metallica-fans.com" contains "meta")
                  "brand_is_whole_label": whole_label,
                  **({"free_hosting": free_suffix} if lured else {})},
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

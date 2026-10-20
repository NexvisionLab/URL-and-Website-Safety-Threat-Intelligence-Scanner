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
from urllib.parse import urlparse

import tldextract

from ..models import Severity, Signal

# Offline public-suffix extractor (no network; uses the bundled snapshot) - same pattern as usi/lookups/rdap.py.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

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
    """True for <brand>.github.io / <brand>.gitlab.io where the single label is exactly a listed brand's name or one of its
    aliases (microsoft.github.io, onedrive.github.io, facebook.github.io). Not 'microsoft-login', and a nested host
    (a.b.github.io) never counts. The content checks (a login form imitating a brand) still run on such a page."""
    for suffix in ORG_NAMESPACE_SUFFIXES:
        if host_l.endswith("." + suffix):
            label = host_l[: -(len(suffix) + 1)]
            return "." not in label and any(
                label == _norm(name) for brand in brands for name in [brand["name"]] + list(brand.get("aliases", []))
            )
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
    exact_name = False
    if free_suffix:
        sub = host_l[: -(len(free_suffix) + 1)]
        digits = sum(c.isdigit() for c in sub) >= 2
        lure_word = any(w in sub for w in _LURE_SUBSTRINGS) or any(w in set(re.split(r"[.\-]", sub)) for w in _LURE_TOKENS)
        # a brand's own official page on such a platform ('microsoft.github.io') is the bare name: not enough on its own
        lured = (whole_label or len(name_l) >= 6) and sub != name_l and (digits or lure_word)
        # A page named exactly like a brand on a host where anyone can claim any name (paypal.weebly.com): the brand does
        # not host its site there. On GitHub/GitLab Pages the same name is the brand's own account, handled above. Names
        # under six letters (apple, steam, zoom) are ordinary words, so a hobby site of that name is not raised.
        exact_name = free_suffix not in ORG_NAMESPACE_SUFFIXES and any(
            len(v) >= 6 and v == _norm(sub.replace("-", "")) for v, _ in _name_variants(matched_brand)
        )
        lured = lured or exact_name

    label = shown if _norm(shown) != _norm(brand_name) else brand_name
    return Signal(
        source="typosquat",
        code="combosquat_keyword_match",
        severity=Severity.HIGH if (keywords or lured) else Severity.MEDIUM,
        message=(
            f"'{host}' contains the brand name '{label}'"
            + (f" alongside {', '.join(repr(k) for k in keywords)}" if keywords else "")
            + " but is not one of its known domains - a common combosquat pattern. "
            + (
                f"It is a page named exactly like the brand on a free hosting service ({free_suffix}), where anyone can pick "
                "a name and the brand does not host its site. " if exact_name
                else f"It is a page on a free hosting service ({free_suffix}), where anyone can pick a name. " if lured else ""
            )
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


def _lev_le1(a: str, b: str) -> bool:
    """True if a and b are equal or within one edit (insert, delete, or substitute a single character)."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    i = 0
    while i < min(la, lb) and a[i] == b[i]:
        i += 1
    if la == lb:          # substitution: the rest after the differing char must match
        return a[i + 1:] == b[i + 1:]
    if la > lb:           # a has one extra char
        return a[i + 1:] == b[i:]
    return a[i:] == b[i + 1:]  # b has one extra char


def _meaningful_labels(host_l: str) -> "list[str]":
    """The host's labels minus its public suffix: subdomain labels plus the registrable label.
    'teams.live.com' -> ['teams', 'live']; 'team.lives.cn.com' -> ['team', 'lives']."""
    ext = _EXTRACT(host_l)
    labels = [p for p in ext.subdomain.split(".") if p] if ext.subdomain else []
    if ext.domain:
        labels.append(ext.domain)
    return labels or host_l.split(".")[:-1]


def find_brand_domain_lookalike(host: str, brands: "list[dict]") -> "Signal | None":
    """A host that imitates a brand's multi-label service DOMAIN by near-matching its labels, even
    across a different public suffix: 'team.lives.cn.com' -> 'teams.live.com'. The name/alias
    combosquat check keys on the brand NAME (the labels 'teams'/'live' are neither Microsoft's name
    nor an alias), and the single-edit candidate generator never reaches a two-edit, suffix-swapped
    variant - so both miss this shape. Only brand domains with a service-style subdomain
    (teams.microsoft.com, meet.google.com) are considered, never a plain or ccTLD domain
    (amazon.com.au), and at least two labels of >=3 characters must each near-match (edit distance
    <=1), so an ordinary word like 'live' or 'team' on its own cannot trip it."""
    host_l = host.lower().strip(".")
    if _is_known_brand_host(host_l, brands):
        return None
    host_labels = _meaningful_labels(host_l)
    if len(host_labels) < 2:
        return None
    for brand in brands:
        for domain in brand["domains"]:
            ext = _EXTRACT(domain.lower())
            if not ext.subdomain or not ext.domain:
                continue  # need a service subdomain, not a plain or ccTLD domain
            sig = [p for p in ext.subdomain.split(".") if p] + [ext.domain]
            if len(sig) < 2 or any(len(s) < 3 for s in sig):
                continue
            n = len(sig)
            for start in range(0, len(host_labels) - n + 1):
                window = host_labels[start:start + n]
                if all(_lev_le1(window[k], sig[k]) for k in range(n)):
                    if window == sig and start == 0 and len(host_labels) == n:
                        continue  # identical signature, nothing else (a real brand host is already excluded above)
                    return Signal(
                        source="typosquat",
                        code="brand_domain_lookalike",
                        severity=Severity.HIGH,
                        message=(
                            f"'{host}' closely matches the domain labels of '{domain}' ({brand['name']}) "
                            "but is a different registrable domain - a common lookalike of a brand's service "
                            f"subdomain. The real {brand['name']} domain is {domain}."
                        ),
                        evidence={"host": host, "brand": brand["name"], "resembles_domain": domain,
                                  "matched_labels": window, "real_domains": brand["domains"][:3]},
                    )
    return None


# A short list of "com.<cc>" second-level public suffixes seen used to impersonate a brand's plain '.com'
# domain (roblox.com.am, paypal.com.de): at a glance these read like a genuine regional domain the way
# amazon.com.au or amazon.co.jp really are, but nothing in brands.json uses any of these particular country
# codes for a real brand domain today - find_cctld_combo_lookalike double-checks that per brand anyway, so a
# brand that later adds a genuine 'com.<cc>' in this list is still excluded automatically.
_CCTLD_COMBO_SUFFIX = re.compile(r"^com\.(?:am|de|vc|cm|sb|bz|gt|pl|se|ro|hr)$")


def _has_cctld_combo_domain(brand: dict) -> bool:
    return any((_EXTRACT(d.lower()).suffix or "").startswith("com.") for d in brand["domains"])


def find_cctld_combo_lookalike(host: str, brands: "list[dict]") -> "Signal | None":
    """'<brand>.com.<cc>' impersonating a brand whose real domain is a plain '<brand>.com' - a real phishing
    case (roblox.com.am for roblox.com). 'com.<cc>' is a genuine two-label public suffix (the same shape as
    amazon.com.au), so it is never generated by the single-edit candidate list or caught by the exact-name
    ALT_TLDS swap (which only appends a single-label TLD). Fires only on an EXACT brand-name match - the
    same precedent the ALT_TLDS swap already uses - with a name of >=6 characters, so an ordinary short word
    used as a brand name (apple, zoom, steam) cannot trip it on its own; and only when the brand has no
    genuine 'com.<cc>' domain anywhere in its list, so amazon.com.au, paypal.com.br etc. stay clean."""
    host_l = host.lower().strip(".")
    if _is_known_brand_host(host_l, brands):
        return None
    ext = _EXTRACT(host_l)
    if not ext.domain or not ext.suffix or not _CCTLD_COMBO_SUFFIX.match(ext.suffix):
        return None
    for brand in brands:
        if _has_cctld_combo_domain(brand):
            continue
        for name_l, shown in _name_variants(brand):
            if len(name_l) < 6 or name_l != ext.domain:
                continue
            real_domain = _real_domain_for(brand, shown)
            return Signal(
                source="typosquat",
                code="cctld_combo_lookalike",
                severity=Severity.HIGH,
                message=(
                    f"'{host}' uses the exact name '{shown}' followed by '.{ext.suffix}', a pattern used to "
                    f"imitate a brand's plain domain with what looks like a genuine regional site - but "
                    f"{brand['name']} has no such domain. The real {brand['name']} website is {real_domain}."
                ),
                evidence={"host": host, "brand": brand["name"], "real_domain": real_domain,
                          "real_domains": brand["domains"][:3]},
            )
    return None


def run_all(host: str, brands: "list[dict] | None" = None) -> "list[Signal]":
    brands = brands if brands is not None else load_brands()
    match = find_typosquat_match(host, brands)
    if match:
        return [match]
    lookalike = find_brand_domain_lookalike(host, brands)
    if lookalike:
        return [lookalike]
    cctld_combo = find_cctld_combo_lookalike(host, brands)
    if cctld_combo:
        return [cctld_combo]
    combosquat = find_combosquat_keyword_match(host, brands)
    if combosquat:
        return [combosquat]
    fuzzy = find_fuzzy_brand_token_match(host, brands)
    return [fuzzy] if fuzzy else []


def find_brand_in_path_lookalike(url: str, host: str, brands: "list[dict]") -> "Signal | None":
    """A brand name that appears only in the URL PATH, not the host at all - a documented real case
    (verifiedbadge-celestine.vercel.app/meta-verified-for-business impersonating Meta). Every other check
    here looks only at the HOST; a host with no brand reference whatsoever sails through them even when
    the page it points at clearly targets that brand by name in its own address.

    Only applies on a free-hosting suffix (FREE_HOSTING_SUFFIXES) the operator of this page does not
    control exclusively - github.io/gitlab.io are excluded the same way is_official_org_page already
    excludes them from the host-based check. The brand name must stand as its own path segment/token
    (split on the usual URL separators), never a substring of an unrelated word, AND a lure word
    (verify, login, support, official, security...) must appear in the same path - a brand name alone in
    a URL path is extremely common and harmless (a review, a blog post, an affiliate link), so the lure
    word is what actually distinguishes an impersonation attempt from ordinary mention."""
    host_l = host.lower().strip(".")
    if _is_known_brand_host(host_l, brands) or is_official_org_page(host_l, brands):
        return None
    free_suffix = _free_host_suffix(host_l)
    if not free_suffix:
        return None
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    path_l = f"{parsed.path or ''}?{parsed.query or ''}".lower()
    tokens = {t for t in re.split(r"[/\-_.?&=]+", path_l) if t}
    if not tokens:
        return None
    lure = any(w in path_l for w in _LURE_SUBSTRINGS) or any(w in tokens for w in _LURE_TOKENS)
    if not lure:
        return None
    for brand in brands:
        for name_l, shown in _name_variants(brand):
            if len(name_l) < 4 or name_l not in tokens:
                continue
            real_domain = _real_domain_for(brand, shown)
            return Signal(
                source="typosquat",
                code="brand_in_path_lookalike",
                severity=Severity.HIGH,
                message=(
                    f"The address path names '{shown}' alongside wording like verification or support, on "
                    f"'{host}' ({free_suffix}), a free hosting service where anyone can publish any page - "
                    f"not {brand['name']}'s own site. The real {brand['name']} website is {real_domain}."
                ),
                evidence={"host": host, "brand": brand["name"], "real_domain": real_domain,
                          "real_domains": brand["domains"][:3], "free_hosting": free_suffix},
            )
    return None


def _name_candidates(name_l: str) -> "set[str]":
    """The same narrow, well-tested perturbation set generate_candidates() uses for a brand's own domain -
    character omission, adjacent transposition, repetition, digit-homoglyph substitution - applied to the
    bare brand name alone (a throwaway TLD gets the splitting machinery to run, then is stripped back off).
    Deliberately NOT a blanket single-edit-distance check: an arbitrary letter substitution is not one of
    these perturbations, which is what keeps this from matching an unrelated ordinary word that merely
    happens to differ from a brand name by one letter (see find_fuzzy_brand_token_match)."""
    raw = generate_candidates(f"{name_l}.x")
    return {c[:-2] for c in raw if c.endswith(".x") and "-" not in c}


def find_fuzzy_brand_token_match(host: str, brands: "list[dict]") -> "Signal | None":
    """A brand name misspelled by one typo-shaped edit, standing as its own token in a longer free-hosting
    host: not-start-eng-trezr.pages.dev for Trezor ('trezr' = 'trezor' with the 'o' omitted - a documented
    real miss from the 2026-09-27 OpenPhish sample). The existing typosquat check only compares the WHOLE
    investigated host against a brand's own full-domain candidates, and the combosquat check only matches
    an EXACT brand-name substring - neither catches a misspelled brand name embedded inside an unrelated,
    longer host.

    Reuses generate_candidates' own narrow name-level perturbations (_name_candidates) rather than any
    single-character substitution: that is what keeps this from flagging an ordinary word that coincidentally
    differs from a long brand name by one letter ('cooking' is not reachable from 'Booking' by omission,
    transposition, repetition or homoglyph substitution, so it is never a candidate; likewise 'googles' from
    'Google'). Brand name must be >=6 characters (confirmed by sweeping ~150 ordinary English words against
    every brand name in brands.json, down to a single genuine coincidence before this reuse closed it), and
    this only applies on a free-hosting suffix - the same 'anyone can claim any name here' precedent already
    used throughout this file - never an arbitrary domain, where a one-letter coincidence is far more likely
    to be an unrelated site than an impersonation attempt."""
    host_l = host.lower().strip(".")
    if _is_known_brand_host(host_l, brands):
        return None
    free_suffix = _free_host_suffix(host_l)
    if not free_suffix:
        return None
    tokens = {t for t in re.split(r"[.\-_]", host_l) if t}
    if not tokens:
        return None
    for brand in brands:
        for name_l, shown in _name_variants(brand):
            if len(name_l) < 6:
                continue
            hit = tokens & _name_candidates(name_l)
            if not hit:
                continue
            misspelled = next(iter(hit))
            real_domain = _real_domain_for(brand, shown)
            return Signal(
                source="typosquat",
                code="fuzzy_brand_token_match",
                severity=Severity.HIGH,
                message=(
                    f"'{host}' contains '{misspelled}', a one-character misspelling of the brand name "
                    f"'{shown}', on '{free_suffix}', a free hosting service where anyone can publish any page. "
                    f"The real {brand['name']} website is {real_domain}."
                ),
                evidence={"host": host, "brand": brand["name"], "misspelled_as": misspelled,
                          "real_domain": real_domain, "real_domains": brand["domains"][:3],
                          "free_hosting": free_suffix},
            )
    return None

"""Network matching: shops that share an operator's fingerprints.

Fake shops are run in networks - one operator, many domains - and the
domains share things a genuine independent shop wouldn't share with
strangers: the same analytics or advertising-pixel account, the same
underlying Shopify store, the same contact email or phone number, the
same business registration number, the same (non-platform) server.

The fingerprints of shops that showed warning signs of their own (High or
Elevated before any network evidence) are kept in a local database
(USI_SHOP_NETWORK_DB, default cache/shop_network.sqlite3) for a year: the
shop's web address, its fingerprints, when it was checked and that band.
Shops that check out clean are not kept, and nothing records who asked.
A new shop is compared against the kept ones:

  "shares its tracking ID with 12 other shops we have checked, 9 of which
   were rated High risk"

Deliberately not used: page templates and themes (thousands of genuine
Shopify shops share the same theme), favicons, and addresses on large
shared platforms (data/shared_hosting.json).

Bands stored are the pre-network band, so two shops can never push each
other up. Reports carry counts only - never which other shops were
checked."""
import ipaddress
import json
import os
import re
import sqlite3
import time
from pathlib import Path

from ..lookups.rdap import registrable_domain
from ..models import Severity, Signal
from .pages import Page

SOURCE = "shop_copy"
DATA = Path(__file__).resolve().parent.parent.parent / "data"
DB_ENV = "USI_SHOP_NETWORK_DB"
DEFAULT_DB = Path(__file__).resolve().parent.parent.parent / "cache" / "shop_network.sqlite3"
RETENTION_DAYS = 365

# (kind, pattern) - each captures one identifier. Matched on the raw HTML, scripts included.
_ID_PATTERNS = [
    ("google_analytics", r"\b(G-[A-Z0-9]{8,12})\b"),
    ("google_analytics", r"\b(UA-\d{4,10}-\d{1,4})\b"),
    ("google_tag_manager", r"\b(GTM-[A-Z0-9]{5,9})\b"),
    ("google_ads", r"\b(AW-\d{9,11})\b"),
    ("facebook_pixel", r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{12,20})['\"]"),
    ("tiktok_pixel", r"ttq\.load\(\s*['\"]([A-Z0-9]{15,25})['\"]"),
    ("pinterest_tag", r"pintrk\(\s*['\"]load['\"]\s*,\s*['\"](\d{10,16})['\"]"),
    ("microsoft_clarity", r"clarity\.ms/tag/([a-z0-9]{8,12})"),
    ("hotjar", r"\bhjid\s*:\s*(\d{6,9})"),
    ("klaviyo", r"klaviyo\.com/onsite/js/klaviyo\.js\?company_id=([A-Za-z0-9]{6})"),
    ("shopify_store", r"\b([a-z0-9][a-z0-9-]{1,60})\.myshopify\.com\b"),
]
_ID_RES = [(k, re.compile(p)) for k, p in _ID_PATTERNS]
# Identifiers that ship with themes or platforms themselves and so appear on unrelated shops.
_GENERIC = {("shopify_store", "shops"), ("shopify_store", "checkout"), ("shopify_store", "cdn")}
STRONG = {"google_analytics", "google_tag_manager", "google_ads", "facebook_pixel", "tiktok_pixel", "pinterest_tag",
          "microsoft_clarity", "hotjar", "klaviyo", "shopify_store", "email", "phone", "uen", "server"}
_LABELS = {
    "google_analytics": "Google Analytics account", "google_tag_manager": "Google Tag Manager container",
    "google_ads": "Google Ads account", "facebook_pixel": "Facebook pixel", "tiktok_pixel": "TikTok pixel",
    "pinterest_tag": "Pinterest tag", "microsoft_clarity": "Microsoft Clarity project", "hotjar": "Hotjar site",
    "klaviyo": "Klaviyo account", "shopify_store": "underlying Shopify store", "email": "contact email",
    "phone": "phone number", "uen": "business registration number", "server": "server",
}
# Contact addresses of platforms and services that appear on unrelated shops' pages.
_PLATFORM_EMAIL_DOMAINS = {"shopify.com", "wix.com", "squarespace.com", "bigcommerce.com", "woocommerce.com",
                           "paypal.com", "stripe.com", "google.com", "apple.com", "facebook.com", "meta.com",
                           "klaviyo.com", "mailchimp.com", "zendesk.com", "gorgias.com", "tiktok.com"}


def _shared_ranges():
    data = json.loads((DATA / "shared_hosting.json").read_text(encoding="utf-8"))
    return [ipaddress.ip_network(r) for p in data["platforms"] for r in p["ranges"]]


_ranges = None


def on_shared_platform(address: str) -> bool:
    global _ranges
    if _ranges is None:
        _ranges = _shared_ranges()
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    return any(ip in net for net in _ranges if net.version == ip.version)


def extract(pages: "list[Page]", contacts: dict, uens: "list[str]", addresses: "list[str]") -> "set[tuple[str, str]]":
    """The shop's fingerprints as (kind, value) pairs."""
    found: "set[tuple[str, str]]" = set()
    for page in pages:
        for kind, rx in _ID_RES:
            for value in rx.findall(page.html or ""):
                pair = (kind, value.lower() if kind == "shopify_store" else value)
                if pair not in _GENERIC:
                    found.add(pair)
    for email in contacts.get("emails", []):
        if email.rsplit("@", 1)[-1].lower() not in _PLATFORM_EMAIL_DOMAINS:
            found.add(("email", email.lower()))
    for phone in contacts.get("phones", []):
        digits = re.sub(r"\D", "", phone)
        if len(digits) >= 8:
            found.add(("phone", digits[-9:]))  # the last nine digits survive +65 / 0065 / spacing differences
    for uen in uens:
        found.add(("uen", uen.upper()))
    for address in addresses:
        if not on_shared_platform(address):
            found.add(("server", address))
    return found


def _db_path() -> Path:
    return Path(os.environ.get(DB_ENV) or DEFAULT_DB)


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE IF NOT EXISTS shops (site TEXT PRIMARY KEY, band TEXT, checked REAL)")
    conn.execute("CREATE TABLE IF NOT EXISTS prints (site TEXT, kind TEXT, value TEXT, PRIMARY KEY (site, kind, value))")
    conn.execute("CREATE INDEX IF NOT EXISTS prints_value ON prints (kind, value)")
    return conn


def match(site: str, prints: "set[tuple[str, str]]") -> dict:
    """Other shops sharing a strong fingerprint: {kind: {"shops": n, "high": n, "elevated": n}}."""
    strong = [p for p in prints if p[0] in STRONG]
    if not strong:
        return {}
    cutoff = time.time() - RETENTION_DAYS * 86400
    out: dict = {}
    try:
        conn = _connect()
        try:
            for kind, value in strong:
                rows = conn.execute(
                    "SELECT s.site, s.band FROM prints p JOIN shops s ON s.site = p.site "
                    "WHERE p.kind = ? AND p.value = ? AND p.site != ? AND s.checked >= ?",
                    (kind, value, site, cutoff)).fetchall()
                if rows:
                    entry = out.setdefault(kind, {"shops": set(), "high": set(), "elevated": set()})
                    for other, band in rows:
                        entry["shops"].add(other)
                        if band == "High":
                            entry["high"].add(other)
                        elif band == "Elevated":
                            entry["elevated"].add(other)
        finally:
            conn.close()
    except sqlite3.Error:
        return {}
    return {k: {n: len(v[n]) for n in ("shops", "high", "elevated")} for k, v in out.items()}


def remember(site: str, band: str, prints: "set[tuple[str, str]]") -> None:
    """Store (or replace) this shop's fingerprints and its pre-network band."""
    try:
        conn = _connect()
        try:
            with conn:
                conn.execute("INSERT OR REPLACE INTO shops VALUES (?, ?, ?)", (site, band, time.time()))
                conn.execute("DELETE FROM prints WHERE site = ?", (site,))
                conn.executemany("INSERT OR IGNORE INTO prints VALUES (?, ?, ?)",
                                 [(site, k, v) for k, v in prints])
                cutoff = time.time() - RETENTION_DAYS * 86400
                old = [r[0] for r in conn.execute("SELECT site FROM shops WHERE checked < ?", (cutoff,))]
                conn.executemany("DELETE FROM prints WHERE site = ?", [(s,) for s in old])
                conn.execute("DELETE FROM shops WHERE checked < ?", (cutoff,))
        finally:
            conn.close()
    except sqlite3.Error:
        pass


def site_key(host: str) -> str:
    return registrable_domain(host) or host.lower()


def signals(matches: dict, established_and_clean: bool = False) -> "list[Signal]":
    """`established_and_clean`: this shop's own evidence was clean (Low) and its domain is over a year old.
    Fake shops copy real shops' pages - contact details and even tracking IDs included - so for such a shop,
    sharing fingerprints with High-rated shops is only noted: network evidence may make a suspicious or new
    shop look worse, never turn an established clean one into a warning."""
    if not matches:
        return []
    shops = max(m["shops"] for m in matches.values())
    high = max(m["high"] for m in matches.values())
    elevated = max(m["elevated"] for m in matches.values())
    kinds = sorted(matches, key=lambda k: (-matches[k]["high"], -matches[k]["shops"]))
    what = ", ".join(_LABELS.get(k, k) for k in kinds[:3])
    evidence = {"shared": {k: matches[k] for k in kinds[:6]}}
    if high and established_and_clean:
        return [Signal(
            source=SOURCE, code="shop_network_copied", severity=Severity.INFO,
            message=(f"This shop shares its {what} with {shops} other shop(s) that showed warning signs, {high} of them "
                     "rated High risk. This shop's own record is clean and long-standing, so the likelier explanation is "
                     "that fake shops copied it."),
            evidence=evidence,
        )]
    if high:
        return [Signal(
            source=SOURCE, code="shop_network_high_risk", severity=Severity.MEDIUM,
            message=(f"This shop shares its {what} with {shops} other shop(s) that showed warning signs, {high} of them "
                     "rated High risk. Fake shops are run in networks that reuse the same accounts and details."),
            evidence=evidence,
        )]
    if shops >= 3 and not established_and_clean:
        return [Signal(
            source=SOURCE, code="shop_network", severity=Severity.LOW,
            message=(f"This shop shares its {what} with {shops} other shops that showed warning signs (none rated High). "
                     "One operator running several shops is common in both genuine groups and fake-shop networks."),
            evidence=evidence,
        )]
    return [Signal(
        source=SOURCE, code="shop_network_small", severity=Severity.INFO,
        message=f"This shop shares its {what} with {shops} other shop(s) that showed warning signs.",
        evidence=evidence,
    )]

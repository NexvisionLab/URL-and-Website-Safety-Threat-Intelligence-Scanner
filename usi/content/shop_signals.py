"""Lightweight, gated reuse of the structural shop checks (usi/shop/) for the GENERAL URL checker.

The embedding classifier's 'scam-shop' category cannot discriminate a real shop from a scam shop: a
margin-based (scam-shop score minus legitimate score) rescoring was tested and falsified (2026-10-21) -
real major retailers (target.com, walmart.com, paypal.com...) score nearly as close to the 'scam-shop'
description as synthetic scam text does, because ordinary retail marketing language (discounts, urgency,
calls to buy) sits close to both category descriptions in embedding space. Raising the threshold enough to
stop false-positiving real sites also makes it miss most real scam-shop text.

usi/shop/ already solves this well for the DEDICATED shop checker (contact, payment, catalogue-discount,
policy and template signals - concrete and structural, not semantic similarity), but investigate_shop() is
a heavy, multi-step investigation (its own pipeline.run(), RDAP, a possible browser render, a product-feed
fetch, cross-shop fingerprinting) not meant to run on every general URL check.

This module is the bounded middle ground: a cheap, single-page gate (no network) on the page the general
pipeline already fetched decides whether a page LOOKS like a shop; only then does it fetch a small, capped
set of extra pages (contact/about/refund/terms - pages.pick_extra_pages, the same cap the full analyzer
uses) and run the concrete structural checks against the whole set.

A single-page-only version was tried first and rejected: it false-positived shop_no_contact on 7 of 10 real
major retailers, because none of them put contact details on the HOMEPAGE text itself - that information
lives on a separate Contact page, which only a multi-page fetch reaches.

Deliberately excluded (kept in investigate_shop() only, for the dedicated shop checker): RDAP (domain age is
reused from the general pipeline's own whois signal instead - no fresh registration lookup here), the
Shopify/WooCommerce product-feed fetch, browser rendering, Singapore UEN lookup, and cross-shop
fingerprint/reputation tracking."""
import re

from ..models import Signal
from ..shop import analyzer as shop_analyzer
from ..shop import catalogue, contact, pages

_PRICE_RE = re.compile(r"(?:[$£€¥]|USD|SGD|EUR|GBP|AUD|CAD)\s?\d[\d,]*(?:\.\d{1,2})?", re.IGNORECASE)
_CTA_RE = re.compile(
    r"\badd to (?:cart|bag|basket)\b|\bbuy now\b|\bshop now\b|\bcheckout\b|\bproceed to checkout\b",
    re.IGNORECASE,
)


def looks_like_shop(raw_html: str, text: str) -> bool:
    """Cheap, single-page, no-network gate: a recognised shop platform, or a price shown alongside a
    buy/cart/checkout call to action. Deliberately requires BOTH a price and a buying prompt together - a
    page that merely mentions a price (a news article, a product review) should not gate the extra fetches
    below."""
    if catalogue.detect_platform(raw_html):
        return True
    t = text or ""
    return bool(_PRICE_RE.search(t) and _CTA_RE.search(t))


def check(url: str, host: str, raw_html: str, url_signals: "list[Signal]", config) -> "list[Signal]":
    """Only call this when looks_like_shop() has already returned True. Fetches up to a few extra,
    same-site pages (contact/about/refund/terms) and runs the structural checks against the whole set.

    Mirrors investigate_shop()'s own _page_checks() split: discount and payment detection run
    unconditionally (pure text-pattern checks, need no "readability"), but the CONTACT-MISSING inference
    only runs when the page is readable (enough server-rendered text/links) - on a script-built page, an
    apparent absence of contact details proves nothing, so that case gets an informational note instead of
    a false "no contact found" signal."""
    main = pages.parse_page(url, raw_html)
    links_by_kind = pages.classify_links(main, host)
    extra_urls = pages.pick_extra_pages(links_by_kind, main.url)
    fetcher = pages.Fetcher(config.fetch_user_agent,
                            tor_proxy=config.tor_proxy if host.lower().endswith(".onion") else None)
    extra = [pg for pg in (fetcher.page(u) for u in extra_urls) if pg is not None and not pages.is_challenge(pg)]
    all_pages = [main] + extra
    texts = [pg.text for pg in all_pages]

    signals: "list[Signal]" = []
    signals += catalogue.signals_from_badges(catalogue.badge_discounts(main.text))

    from ..shop import payment
    found = payment.detect([pg.html for pg in all_pages], texts)
    signals += payment.signals(found)

    if pages.is_readable(main):
        contacts = contact.find_contacts(all_pages)
        signals += contact.contact_signals(contacts, footer_seen=bool(links_by_kind))
        signals += contact.policy_signals(links_by_kind)
        signals += contact.template_signals(all_pages)
        signals += contact.seal_signals(main)

    age_days = shop_analyzer._age_days_from(url_signals)
    signals += shop_analyzer.age_signals(age_days, registrant=None)

    return signals

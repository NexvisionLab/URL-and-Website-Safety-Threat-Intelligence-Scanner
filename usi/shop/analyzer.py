"""investigate_shop(): the shop analyzer's one entry point.

1. A link to a marketplace, social network or chat app is recognised
   first (platforms.py) and answered with that platform's safety rating
   and advice about the seller - the website itself isn't the question.
2. Otherwise the full URL investigation runs (pipeline.run), which also
   hands back the page it fetched.
3. The shop checks run on that page plus a few linked pages and the
   shop's public product feed: registration age (RDAP), discounts and
   catalogue age, payment methods, contact details and policies,
   template leftovers, trust seals, brand use, and the Singapore UEN.
4. The buyer's own answers (claims.py) are added, and rules.py turns the
   evidence into a risk band with named reasons.

Steps 2-3 are cached like URL results (key "shop:<url>"); the buyer's
answers are applied after the cache, so they never leak between people."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .. import cache, pipeline
from ..config import Config
from ..lookups import rdap
from ..models import Severity, Signal
from ..output.formatter import signal_from_dict, signal_to_dict
from . import (address, brands, browser, catalogue, claims, contact, fingerprint, identity, pages, payment, platforms,
               render, rules)

AGE_SOURCE = "shop_age"
NEW_DOMAIN_DAYS = 90
RECENT_DOMAIN_DAYS = 365
CACHE_PREFIX = "shop:"

DISCLAIMER = (
    "This reports warning signs in what the shop's website shows about itself. It is not a finding that the "
    "shop is a scam, and a clean result doesn't prove a shop is genuine."
)


def _age_days_from(url_signals: "list[Signal]") -> "int | None":
    for s in url_signals:
        if s.code in ("young_domain", "domain_age") and isinstance((s.evidence or {}).get("age_days"), int):
            return s.evidence["age_days"]
    return None


def age_signals(age_days: "int | None", registrant: "str | None") -> "list[Signal]":
    out = []
    if age_days is not None:
        if age_days < NEW_DOMAIN_DAYS:
            out.append(Signal(
                source=AGE_SOURCE, code="shop_domain_new", severity=Severity.MEDIUM,
                message=(f"The shop's web address was registered only {age_days} day(s) ago. Most fake shops are "
                         "set up shortly before they advertise and vanish within weeks."),
                evidence={"age_days": age_days},
            ))
        elif age_days < RECENT_DOMAIN_DAYS:
            out.append(Signal(
                source=AGE_SOURCE, code="shop_domain_recent", severity=Severity.LOW,
                message=f"The shop's web address was registered {age_days} days ago - less than a year.",
                evidence={"age_days": age_days},
            ))
        else:
            out.append(Signal(
                source=AGE_SOURCE, code="shop_domain_age", severity=Severity.INFO,
                message=f"The shop's web address was registered {age_days // 365} year(s) ago.",
                evidence={"age_days": age_days},
            ))
    else:
        out.append(Signal(
            source=AGE_SOURCE, code="shop_domain_age_unavailable", severity=Severity.INFO,
            message="We couldn't find when the shop's web address was registered.",
        ))
    if registrant:
        out.append(Signal(
            source="shop_identity", code="shop_domain_registrant", severity=Severity.INFO,
            message=f"The domain registry lists the web address as registered to {registrant}.",
            evidence={"registrant": registrant},
        ))
    return out


def _host_checks(host: str, url_signals: "list[Signal]", reg: "dict | None") -> "tuple[list[Signal], dict]":
    """What can be judged from the web address alone - so it still counts when the page itself
    can't be seen (blocked, down, or behind a bot check)."""
    age_days = _age_days_from(url_signals)
    if age_days is None and reg and reg.get("created"):
        age_days = (datetime.now(timezone.utc) - reg["created"]).days
    signals = age_signals(age_days, (reg or {}).get("registrant"))
    signals += brands.signals(host, "", "", brands.load())
    return signals, {"domain_age_days": age_days}


def _page_checks(main: pages.Page, host: str, fetcher: pages.Fetcher, pool: ThreadPoolExecutor,
                 age_days: "int | None", config: Config, truncated: bool = False,
                 rendered: bool = False) -> "tuple[list[Signal], dict]":
    """`rendered`: the main page needed a browser. Its linked pages are still fetched plainly and may be
    script-built too, so missing contact details there are only noted, not weighed."""
    facts: dict = {}
    links_by_kind = pages.classify_links(main, host)
    platform = catalogue.detect_platform(main.html)
    feed = catalogue.feed_url(platform, main.url) if platform else None
    page_futures = [pool.submit(fetcher.page, u) for u in pages.pick_extra_pages(links_by_kind, main.url)]
    feed_data = pool.submit(fetcher.json, feed).result() if feed else None
    extra = [pg for pg in (f.result() for f in page_futures) if pg is not None and not pages.is_challenge(pg)]

    all_pages = [main] + extra
    texts = [pg.text for pg in all_pages]
    facts["pages_checked"] = [pg.url for pg in all_pages]
    facts["shop_platform"] = platform
    readable = pages.is_readable(main)
    facts["page_readable"] = readable
    facts["page_truncated"] = truncated
    signals: "list[Signal]" = []

    # Discounts and catalogue age.
    items = []
    if platform == "shopify" and feed_data is not None:
        items = catalogue.parse_shopify(feed_data)
    elif platform == "woocommerce" and feed_data is not None:
        items = catalogue.parse_woocommerce(feed_data)
    if items:
        summary = catalogue.summarise(items)
        facts["catalogue"] = summary
        signals += catalogue.signals_from_feed(summary, platform, age_days)
    else:
        signals += catalogue.signals_from_badges(catalogue.badge_discounts(main.text))

    # Payment.
    found = payment.detect([pg.html for pg in all_pages], texts)
    facts["payment_methods"] = found
    signals += payment.signals(found)

    # Contact and policies need readable pages: on a page built entirely by script, finding
    # nothing proves nothing.
    contacts = contact.find_contacts(all_pages)
    facts["contact"] = contacts
    if truncated:
        # The fetch stops at fetch_max_bytes; on a very large page the footer, where contact
        # details and policy links usually are, may be past the cut.
        if contacts["emails"] or contacts["phones"] or contacts["addresses"]:
            signals += contact.contact_signals(contacts)
        signals.append(Signal(
            source="shop_identity", code="shop_page_too_large", severity=Severity.INFO,
            message="The shop's front page is too large to read in full, so missing contact details or policies aren't counted.",
        ))
    elif readable:
        signals += contact.contact_signals(contacts, footer_seen=bool(links_by_kind) and not rendered)
        signals += contact.policy_signals(links_by_kind)
    else:
        signals.append(Signal(
            source="shop_identity", code="shop_page_scripted", severity=Severity.INFO,
            message=("The shop's page is built by script, so we couldn't read its contact details or policies. "
                     "Look for them yourself before buying."),
        ))
    signals += contact.template_signals(all_pages)
    signals += contact.seal_signals(main)

    # A page calling itself an official store of a brand (the address was checked already).
    signals += [sg for sg in brands.signals(host, main.title or "", main.text, brands.load())
                if sg.code == "shop_official_claim"]

    # Singapore business registration.
    uens = identity.find_uens(texts)
    lookups = {u: identity.lookup(u, config.cache_path) for u in uens}
    singaporean = identity.looks_singaporean(host, texts, contacts["phones"], contacts["addresses"])
    facts["uens"] = uens
    facts["presents_as_singaporean"] = singaporean
    haystack = " ".join([host, main.title or ""] + texts)
    signals += identity.signals(uens, lookups, singaporean, haystack)
    facts["_prints"] = sorted(fingerprint.extract(all_pages, contacts, uens, []))
    return signals, facts


def _examinable(fetch_result) -> "pages.Page | None":
    """The shop's main page, if what came back is really the shop: a 2xx HTML page, not an error
    page or a bot-protection interstitial."""
    if not fetch_result or not fetch_result.reachable or not fetch_result.text:
        return None
    if not (fetch_result.http_status and 200 <= fetch_result.http_status < 300):
        return None
    main = pages.parse_page(fetch_result.final_url or "", fetch_result.text)
    return None if pages.is_challenge(main) else main


def _shop_checks(url: str, host: str, fetch_result, url_signals: "list[Signal]",
                 config: Config) -> "tuple[list[Signal], dict, bool]":
    is_onion = host.lower().endswith(".onion")
    fetcher = pages.Fetcher(config.fetch_user_agent,
                            tor_proxy=config.tor_proxy if (is_onion or config.tor_enabled) else None)
    main = _examinable(fetch_result)
    renderer = None if is_onion else render.get_renderer()
    rendered_desktop = None
    used_render = False
    footer_links = bool(main is not None and pages.classify_links(main, host))
    if renderer is not None and (main is None or not pages.is_readable(main) or not footer_links):
        # The plain fetch couldn't read the page, or its footer (contact and policy links) is added
        # by script: try a real browser. It can't get past an interactive bot check (and doesn't
        # try to), but it does run script-built shops.
        rendered_desktop = renderer.render(url, "desktop")
        page = render.as_page(rendered_desktop)
        plain_readable = main is not None and pages.is_readable(main)
        if page is not None and (
                main is None                                                   # plain fetch got nothing usable
                or (not plain_readable and pages.is_readable(page))            # script-built page
                or (plain_readable and pages.classify_links(page, host))):     # footer added by script
            main, used_render = page, True
    with ThreadPoolExecutor(max_workers=6, thread_name_prefix="shop") as pool:
        phone_future = pool.submit(renderer.render, url, "phone_facebook") if renderer is not None else None
        rdap_future = None if is_onion else pool.submit(rdap.registration, host)
        try:
            reg = rdap_future.result() if rdap_future else None
        except Exception:  # noqa: BLE001 - registration data is optional here
            reg = None
        signals, facts = _host_checks(host, url_signals, reg)
        # Address-level evidence (certificate history, known fake-shop hosting, generated names) runs
        # alongside the page checks; it is what's left to go on when the page itself is blocked.
        address_future = None if is_onion else pool.submit(address.check, host, facts["domain_age_days"])
        if main is not None:
            truncated = not used_render and (
                len((fetch_result.text or "").encode("utf-8", errors="ignore")) >= config.fetch_max_bytes - 4096)
            page_signals, page_facts = _page_checks(main, host, fetcher, pool, facts["domain_age_days"], config,
                                                    truncated=truncated, rendered=used_render)
            signals += page_signals
            facts.update(page_facts)
        if phone_future is not None:
            try:
                phone = phone_future.result()
            except Exception:  # noqa: BLE001 - the phone view is optional
                phone = None
            if phone is not None:
                desktop_view = rendered_desktop or browser.Rendered(
                    ok=bool(fetch_result and fetch_result.reachable), profile="desktop",
                    status=getattr(fetch_result, "http_status", None), final_url=getattr(fetch_result, "final_url", None),
                    html=(getattr(fetch_result, "text", None) or ""))
                signals += render.compare_views(desktop_view, phone)
                facts["phone_view"] = {"status": phone.status, "error": phone.error}
        facts["rendered"] = used_render
        if address_future is not None:
            try:
                address_signals, address_facts = address_future.result()
            except Exception:  # noqa: BLE001 - address evidence is optional; never fail the check over it
                address_signals, address_facts = [], {}
            signals += address_signals
            facts.update(address_facts)
    return signals, facts, main is not None


def _network(host: str, url_signals: "list[Signal]", shop_signals: "list[Signal]", facts: dict,
             page_examined: bool, remember: bool = True) -> "list[Signal]":
    """Compare this shop's fingerprints with the shops already checked, then remember it. Other shops are
    judged by the band they got before any network evidence, so shops can never raise each other in a loop."""
    prints = {tuple(p) for p in facts.pop("_prints", [])}
    prints |= fingerprint.extract([], {}, [], facts.get("addresses") or [])
    site = fingerprint.site_key(host)
    base_band, _ = rules.rate(url_signals, shop_signals, page_examined)
    matches = fingerprint.match(site, prints)
    age = facts.get("domain_age_days")
    established_and_clean = base_band == rules.LOW and isinstance(age, int) and age >= 365
    # Only shops with warning signs of their own are kept: those are what a new shop is compared against.
    # A shop that checks out clean isn't recorded at all, and no record says who checked anything.
    if remember and prints and base_band in (rules.HIGH, rules.ELEVATED):
        fingerprint.remember(site, base_band, prints)
    facts["network"] = {"fingerprints": len(prints), "shared": matches}
    return fingerprint.signals(matches, established_and_clean)


def _checklist(signals: "list[Signal]") -> "list[str]":
    codes = {s.code for s in signals}
    items = [
        "Pay by credit card or PayPal, which let you dispute the charge. Don't pay a shop you don't know by bank "
        "transfer, PayNow, crypto or gift cards.",
    ]
    brand = next((s for s in signals if s.code in ("shop_brand_in_address", "shop_official_claim")), None)
    if brand:
        items.append(f"To buy {brand.evidence['brand']}, go to {brand.evidence['real_domains'][0]} yourself "
                     "or to a retailer the brand lists as authorised.")
    if codes & {"shop_deep_discounts", "claim_deep_discount"}:
        items.append("Compare the price with other shops. A price far below everyone else's is the most common "
                     "sign of a fake shop.")
    if codes & {"shop_sg_no_uen", "shop_uen_name_mismatch", "shop_uen_not_found"}:
        items.append("Ask the seller for their registered business name and UEN, and look it up on ACRA's "
                     "BizFile (bizfile.gov.sg).")
    items.append("Search for the shop's name together with 'scam' or 'review' before you pay.")
    items.append("If you have already paid, call your bank at once and report it at police.gov.sg/i-witness. "
                 "For advice, call the ScamShield Helpline on 1799.")
    return items


def _marketplace_result(url: str, host: str, platform: dict, claim_signals: "list[Signal]") -> dict:
    return {
        "kind": platform["kind"],
        "url": url, "host": host,
        "checked_at": datetime.now(timezone.utc).isoformat(), "from_cache": False,
        "risk_band": "Check the seller",
        "rules": [], "page_examined": False,
        "platform": platform,
        "signals": [signal_to_dict(s) for s in claim_signals],
        "url_signals": [], "url_verdict": None, "facts": {},
        "checklist": platform["advice"],
        "disclaimer": (f"{platform['name']} is a genuine platform, so the website itself isn't the risk. "
                       "What matters is the seller and how they ask you to pay."),
    }


def investigate_shop(raw_target: str, config: Config, *, buyer_claims: "dict | None" = None,
                     no_cache: bool = False, no_store: bool = False) -> dict:
    url, host = pipeline.normalize_target(raw_target)
    cleaned_claims = claims.clean(buyer_claims)
    claim_signals = claims.signals(cleaned_claims)

    platform = platforms.identify(url)
    if platform:
        return _marketplace_result(url, host, platform, claim_signals)

    key = CACHE_PREFIX + url
    part = None if no_cache else cache.get(config.cache_path, key, config.cache_ttl_hours)
    from_cache = part is not None
    if part is None:
        sink: dict = {}
        base = pipeline.run(url, config, no_cache=True, no_store=no_store, page_sink=sink)
        url_signals = list(base.verdict.signals)
        shop_signals, facts, page_examined = _shop_checks(url, host, sink.get("fetch"), url_signals, config)
        shop_signals += _network(host, url_signals, shop_signals, facts, page_examined, remember=not no_store)
        part = {
            "url": url, "host": host, "checked_at": base.checked_at,
            "page_examined": page_examined,
            "url_verdict": base.verdict.verdict,
            "url_signals": [signal_to_dict(s) for s in url_signals],
            "shop_signals": [signal_to_dict(s) for s in shop_signals],
            "facts": facts,
            "skipped_layers": base.skipped_layers,
        }
        if not no_store:
            cache.set(config.cache_path, key, part)

    url_signals = [signal_from_dict(d) for d in part["url_signals"]]
    shop_signals = [signal_from_dict(d) for d in part["shop_signals"]] + claim_signals
    band, fired = rules.rate(url_signals, shop_signals, part["page_examined"])
    return {
        "kind": "shop",
        "url": part["url"], "host": part["host"],
        "checked_at": part["checked_at"], "from_cache": from_cache,
        "risk_band": band,
        "rules": fired,
        "page_examined": part["page_examined"],
        "platform": None,
        "signals": [signal_to_dict(s) for s in shop_signals],
        "url_signals": part["url_signals"],
        "url_verdict": part["url_verdict"],
        "facts": part["facts"],
        "skipped_layers": part.get("skipped_layers", []),
        "claims": cleaned_claims,
        "checklist": _checklist(shop_signals),
        "disclaimer": DISCLAIMER,
    }

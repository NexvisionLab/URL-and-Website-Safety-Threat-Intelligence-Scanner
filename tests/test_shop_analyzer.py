"""End-to-end wiring of investigate_shop(): the URL investigation, every
extra request, RDAP and the ACRA register are stubbed, so these run
offline while the real parsing, checks and rules are exercised."""
from datetime import datetime, timedelta, timezone

import pytest

from usi import pipeline
from usi.config import Config
from usi.lookups import rdap
from usi.models import FetchResult, InvestigationResult, Severity, Signal, VerdictReport
from usi.shop import address, analyzer, browser, identity, pages, render

FILLER = "<p>" + "Comfortable walking pads for home and office, quiet motor, foldable frame. " * 8 + "</p>"
FAKE_HOME = """<html><head><title>Walking Pads Clearance</title>
<script src="https://cdn.shopify.com/s/files/theme.js"></script></head><body>
<a href="/pages/contact">Contact</a> <a href="/policies/refund-policy">Refund policy</a>
<img alt="Trusted Shops" src="/trusted.png"> <p>Pay by bank transfer.</p>""" + FILLER + "</body></html>"
SCRIPTED_HOME = '<html><head><title>Acme</title></head><body><div id="root"></div><script src="/app.js"></script></body></html>'
CHALLENGE = "<html><head><title>Just a moment...</title></head><body>Enable JavaScript and cookies to continue</body></html>"

REAL_HOME = """<html><head><title>Acme Home</title></head><body>
<a href="/contact">Contact us</a> <a href="/returns">Returns</a> <a href="/terms">Terms</a>
<p>Acme Trading Pte. Ltd. (UEN 201511638H) 10 Anson Road #12-08 Singapore 079903 +65 6232 6720</p>
<svg><title>Visa</title></svg> <svg><title>PayPal</title></svg></body></html>"""

NOW = datetime.now(timezone.utc)


def _feed(n, price, was, days_old):
    created = (NOW - timedelta(days=days_old)).isoformat()
    return {"products": [{"created_at": created, "variants": [{"price": str(price), "compare_at_price": str(was)}]}
                         for _ in range(n)]}


@pytest.fixture
def stub(monkeypatch, tmp_path):
    state = {"html": FAKE_HOME, "age_days": 12, "extra": {}, "feed": None, "reachable": True,
             "url_extra": [], "rdap": None, "uen": {}, "runs": 0, "cert": False, "ips": []}

    def fake_run(url, config, **kw):
        state["runs"] += 1
        signals = [Signal("whois", "young_domain" if state["age_days"] < 30 else "domain_age",
                          Severity.MEDIUM if state["age_days"] < 30 else Severity.INFO, "age",
                          {"age_days": state["age_days"]})] + state["url_extra"]
        fetch = FetchResult(reachable=state["reachable"], http_status=200, final_url=url,
                            text=state["html"] if state["reachable"] else None)
        if kw.get("page_sink") is not None:
            kw["page_sink"]["fetch"] = fetch
        if not state["reachable"]:
            signals.append(Signal("fetch", "fetch_failed", Severity.INFO, "down"))
        return InvestigationResult(url=url, host="x", is_onion=False, from_cache=False, checked_at=NOW.isoformat(),
                                   verdict=VerdictReport(verdict="Likely Safe", signals=signals))

    monkeypatch.setattr(pipeline, "run", fake_run)
    monkeypatch.setattr(pages.Fetcher, "page", lambda self, u: (
        pages.parse_page(u, state["extra"][u]) if u in state["extra"] else None))
    monkeypatch.setattr(pages.Fetcher, "json", lambda self, u: state["feed"])
    monkeypatch.setattr(rdap, "registration", lambda host, cache_dir=None: state["rdap"])
    monkeypatch.setattr(identity, "lookup", lambda uen, cache_path: state["uen"].get(uen))
    monkeypatch.setattr(address, "first_certificate", lambda domain: state["cert"])
    monkeypatch.setattr(address, "resolve", lambda host: state["ips"])
    monkeypatch.setattr(render, "get_renderer", lambda: None)
    state["config"] = Config(cache_path=str(tmp_path / "cache.sqlite3"))
    return state


def check(stub, url="https://walkingpads.shop/", **kw):
    return analyzer.investigate_shop(url, stub["config"], **kw)


def codes(result):
    return {s["code"] for s in result["signals"]}


def test_mass_produced_fake_shop_is_high(stub):
    stub["feed"] = _feed(40, 29, 99, 10)
    stub["extra"] = {"https://walkingpads.shop/policies/refund-policy": "<p>Returns go to [Store Name].</p>"}
    r = check(stub)
    assert r["risk_band"] == "High"
    assert {"shop_domain_new", "shop_deep_discounts", "shop_catalogue_new", "shop_prepayment_only",
            "shop_no_contact", "shop_template_text", "shop_seal_unlinked"} <= codes(r)
    assert {"new_shop_deep_discounts", "new_shop_unprotected_payment"} <= {x["id"] for x in r["rules"]}
    assert r["facts"]["catalogue"]["products_checked"] == 40
    assert r["checklist"] and r["disclaimer"]


def test_established_registered_shop_is_low(stub):
    stub.update(html=REAL_HOME, age_days=4000)
    stub["uen"] = {"201511638H": {"found": True, "uen": "201511638H", "name": "ACME TRADING PTE. LTD.",
                                  "status": "Registered", "entity_type": "Local Company",
                                  "registered": "2015-04-30", "postal_code": "079903"}}
    r = check(stub, "https://acme.sg/")
    assert r["risk_band"] == "Low", r["rules"]
    assert "shop_uen_verified" in codes(r)
    assert r["facts"]["uens"] == ["201511638H"] and r["facts"]["presents_as_singaporean"]


def test_invented_registration_number_is_high(stub):
    stub.update(html=REAL_HOME, age_days=4000)
    stub["uen"] = {"201511638H": {"found": False, "uen": "201511638H"}}
    r = check(stub, "https://acme.sg/")
    assert r["risk_band"] == "High" and "registration_invalid" in {x["id"] for x in r["rules"]}


def test_script_built_page_is_not_called_contactless(stub):
    stub.update(html=SCRIPTED_HOME, age_days=4000)
    r = check(stub, "https://acme.sg/")
    assert "shop_page_scripted" in codes(r)
    assert not {"shop_no_contact", "shop_no_policies"} & codes(r)
    assert r["risk_band"] == "Low"


def test_front_page_without_any_footer_links_is_not_called_contactless(stub):
    stub.update(html="<html><head><title>Acme Home</title></head><body>" + FILLER + "</body></html>", age_days=4000)
    r = check(stub, "https://acme.sg/")
    assert "shop_contact_not_found" in codes(r) and "shop_no_contact" not in codes(r)


def test_cut_off_page_does_not_count_missing_contacts(stub, monkeypatch):
    stub.update(html=FAKE_HOME, age_days=4000)
    stub["config"].fetch_max_bytes = 1000
    r = check(stub, "https://acme.sg/")
    assert "shop_page_too_large" in codes(r) and "shop_no_contact" not in codes(r)


def test_bot_check_page_is_not_judged_as_the_shop(stub):
    stub.update(html=CHALLENGE, age_days=4000)
    r = check(stub, "https://acme.sg/")
    assert r["page_examined"] is False and r["risk_band"] == "Not enough information"
    assert "shop_no_contact" not in codes(r)


def test_address_checks_still_count_when_the_page_is_blocked(stub):
    stub.update(html=CHALLENGE, age_days=12)
    r = check(stub, "https://eu-segway.com/")
    assert {"shop_domain_new", "shop_brand_in_address"} <= codes(r)
    assert r["page_examined"] is False and r["risk_band"] == "High"


def test_unreachable_page_is_not_enough_information(stub):
    stub.update(reachable=False, age_days=4000)
    r = check(stub)
    assert r["risk_band"] == "Not enough information" and r["page_examined"] is False


def test_marketplace_link_gets_platform_answer_without_fetching(stub):
    r = check(stub, "https://www.carousell.sg/p/pokemon-cards-123/", buyer_claims={"payment_requested": "paynow"})
    assert r["kind"] == "classifieds" and r["risk_band"] == "Check the seller"
    assert r["platform"]["mha_ticks"] == 2 and stub["runs"] == 0
    assert [s["code"] for s in r["signals"]] == ["claim_payment_transfer"]


def test_result_is_cached_but_buyer_answers_are_not(stub):
    stub.update(html=REAL_HOME, age_days=4000)
    first = check(stub, "https://acme.sg/", buyer_claims={"payment_requested": "gift_card"})
    assert first["risk_band"] == "High" and first["from_cache"] is False
    second = check(stub, "https://acme.sg/")
    assert second["from_cache"] is True and stub["runs"] == 1
    assert "claim_payment_irreversible" not in codes(second)


def test_rdap_age_used_when_whois_has_none(stub, monkeypatch):
    stub.update(html=REAL_HOME)
    stub["age_days"] = 4000

    def run_without_age(url, config, **kw):
        kw["page_sink"]["fetch"] = FetchResult(reachable=True, http_status=200, final_url=url, text=REAL_HOME)
        return InvestigationResult(url=url, host="x", is_onion=False, from_cache=False, checked_at=NOW.isoformat(),
                                   verdict=VerdictReport(verdict="Likely Safe", signals=[]))
    monkeypatch.setattr(pipeline, "run", run_without_age)
    stub["rdap"] = {"created": NOW - timedelta(days=20), "registrant": "ACME TRADING PTE. LTD."}
    r = check(stub, "https://acme2.sg/")
    assert r["facts"]["domain_age_days"] == 20
    assert {"shop_domain_new", "shop_domain_registrant"} <= codes(r)


def test_blocked_de_shop_dated_by_its_first_certificate(stub, monkeypatch):
    # .de registries publish no registration date; the certificate log still dates the site.
    def run_without_age(url, config, **kw):
        kw["page_sink"]["fetch"] = FetchResult(reachable=True, http_status=403, final_url=url, text=CHALLENGE)
        return InvestigationResult(url=url, host="x", is_onion=False, from_cache=False, checked_at=NOW.isoformat(),
                                   verdict=VerdictReport(verdict="Likely Safe", signals=[]))
    monkeypatch.setattr(pipeline, "run", run_without_age)
    stub["cert"] = NOW - timedelta(days=12)
    r = check(stub, "https://heizkoerper-profi.de/")
    assert r["page_examined"] is False and "shop_cert_new" in codes(r)
    assert r["risk_band"] == "Elevated" and r["facts"]["first_certificate"]


def test_new_shop_on_known_fake_shop_server_is_high(stub):
    stub["ips"] = ["207.244.126.19"]
    r = check(stub)
    assert "shop_known_fake_hosting" in codes(r)
    assert "known_fake_hosting_new_shop" in {x["id"] for x in r["rules"]} and r["risk_band"] == "High"


class FakeRenderer:
    def __init__(self, views):
        self.views = views
        self.calls = []

    def render(self, url, profile):
        self.calls.append(profile)
        status, html = self.views[profile]
        return browser.Rendered(ok=True, profile=profile, status=status, final_url=url, title="", html=html)


def test_script_built_page_is_read_through_the_browser(stub, monkeypatch):
    stub.update(html=SCRIPTED_HOME, age_days=4000)
    full = REAL_HOME.replace("</body>", FILLER + "</body>")
    fake = FakeRenderer({"desktop": (200, full), "phone_facebook": (200, full)})
    monkeypatch.setattr(render, "get_renderer", lambda: fake)
    stub["uen"] = {"201511638H": {"found": True, "uen": "201511638H", "name": "ACME TRADING PTE. LTD.",
                                  "status": "Registered", "entity_type": "Local Company", "registered": "2015-04-30"}}
    r = check(stub, "https://acme.sg/")
    assert r["facts"]["rendered"] is True and "shop_uen_verified" in codes(r)
    assert "shop_views_consistent" in codes(r) and r["risk_band"] == "Low"
    assert sorted(fake.calls) == ["desktop", "phone_facebook"]


def test_storefront_shown_only_to_facebook_phone_visitors_is_high(stub, monkeypatch):
    stub.update(html="<html><head><title>404</title></head><body>Not Found</body></html>", age_days=4000)
    storefront = FAKE_HOME
    fake = FakeRenderer({"desktop": (404, "<html><head><title>404</title></head><body>Not Found</body></html>"),
                         "phone_facebook": (200, storefront)})
    monkeypatch.setattr(render, "get_renderer", lambda: fake)
    r = check(stub)
    assert "shop_cloaked_for_ads" in codes(r)
    assert r["risk_band"] == "High" and "cloaked_for_ads" in {x["id"] for x in r["rules"]}


def test_no_renderer_means_no_browser_calls(stub, monkeypatch):
    monkeypatch.setattr(render, "get_renderer", lambda: None)
    r = check(stub)
    assert "rendered" in r["facts"] and r["facts"]["rendered"] is False

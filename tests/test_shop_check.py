"""Fake-shop detection. The pages here are synthetic, modelled on the templates fake shops copy, and on what real shops show.
Nothing is fetched."""
import time

import pytest

from usi.content import extractor, shop_check
from usi.models import Severity, Signal
from usi.verdict import aggregator

LEGIT_FOOTER = """
<footer>
  <a href="/pages/contact-us">Contact us</a> <a href="/policies/refund-policy">Returns &amp; refunds</a>
  <a href="/policies/shipping-policy">Shipping</a> <a href="/policies/terms-of-service">Terms of service</a>
  <a href="/policies/privacy-policy">Privacy policy</a>
  <p>Acme Outdoor Pte Ltd, UEN 201912345K, 12 Robinson Road, Singapore 048545. Call +65 6123 4567 or email hello@acme-outdoor.example.
  We accept Visa, Mastercard, PayPal and Apple Pay.</p>
</footer>"""


def products(count, old="$199.00", new="$29.99"):
    return "".join(
        f'<div class="product"><h3>Item {i}</h3><span class="price"><del>{old}</del> <ins>{new}</ins></span>'
        f'<button>Add to cart</button></div>' for i in range(count))


FILLER = "Quality goods chosen for you and delivered to your door. Browse our full range online. " * 8  # a real shop page has plenty of text


def page(title="Shop", body="", footer=LEGIT_FOOTER, extra_head="", filler=FILLER):
    return (f'<html><head><title>{title}</title>{extra_head}<script src="https://cdn.shopify.com/s/files/theme.js"></script></head>'
            f'<body>{body}<p>{filler}</p>{footer}</body></html>')


def run(host, html, prior=None):
    ex = extractor.extract(html, "https://" + host + "/", 200, "https://" + host + "/")
    return shop_check.check(host, ex.title, ex.text, html, prior or [])


def codes(signals):
    return {s.code for s in signals}


def strongest(signals):
    return max((s.severity for s in signals), default=Severity.INFO)


# A classic fake outlet: famous brand on the wrong domain, everything 85% off, a timer, nothing to contact, nothing to
# read, and payment that cannot be reversed.
FAKE_BODY = (
    "<h1>Nike Outlet Store - Official Clearance</h1><p>Up to 90% OFF everything! Sale ends in 02:14:33. Hurry, only 3 left in stock.</p>"
    + products(12) + "<p>Payment: bank transfer or Bitcoin only. Free shipping worldwide.</p>"
)
FAKE_FOOTER = "<footer><a href='/'>Home</a> <a href='/shop'>Shop</a> <a href='/cart'>Cart</a> <p>Copyright 2026 Nike Outlet. All rights reserved.</p></footer>"


def test_a_classic_fake_outlet_is_recognised_and_rated_critical():
    signals = run("nike-outlet-sale.shop", page("Nike Outlet Store - up to 90% off", FAKE_BODY, FAKE_FOOTER))
    found = codes(signals)
    assert {"shop_detected", "shop_extreme_discount", "shop_pressure_tactics", "shop_untraceable_payment", "shop_brand_discount_unofficial",
            "shop_bargain_domain_name", "fake_shop_pattern"} <= found
    assert next(s for s in signals if s.code == "fake_shop_pattern").severity == Severity.CRITICAL
    assert aggregator.rate(signals).verdict == "Likely Malicious"


def test_the_signals_name_what_was_found():
    signals = {s.code: s for s in run("nike-outlet-sale.shop", page("Nike Outlet Store", FAKE_BODY, FAKE_FOOTER))}
    assert signals["shop_extreme_discount"].evidence["claimed_percent"] == 90
    assert signals["shop_extreme_discount"].evidence["deeply_discounted_items"] == 12
    assert "bank transfer" in signals["shop_untraceable_payment"].evidence["methods"]
    assert signals["shop_brand_discount_unofficial"].evidence["official"] == "nike.com"
    assert set(signals["fake_shop_pattern"].evidence["red_flags"]) >= {"discount", "pressure", "no_contact", "no_policies", "payment", "brand"}


# ---------------------------------------------------------------------------- real shops stay quiet

def test_a_genuine_shop_with_a_normal_sale_gets_no_warning():
    body = "<h1>Acme Outdoor</h1><p>Spring sale: 20% off selected jackets. Free shipping over $75.</p>" + products(8, "$120.00", "$96.00")
    signals = run("www.acme-outdoor.example", page("Acme Outdoor", body))
    assert strongest(signals) <= Severity.LOW
    assert "shop_reassuring_signs" in codes(signals)
    assert aggregator.rate(signals).verdict == "Likely Safe"


def test_the_good_signs_are_listed_so_the_report_can_show_them():
    body = "<p>Shop now.</p>" + products(4, "$120.00", "$96.00")
    signs = next(s for s in run("www.acme-outdoor.example", page("Acme", body)) if s.code == "shop_reassuring_signs").evidence["signs"]
    assert {"contact details are shown", "a returns policy is linked", "card or PayPal payment is offered"} <= set(signs)


def test_a_shop_that_sells_gift_cards_is_not_accused_of_taking_gift_cards_as_payment():
    # Regression, found on a real shop: "E-Gift Card" in a footer link made the payment check fire HIGH.
    footer = LEGIT_FOOTER.replace("We accept Visa, Mastercard, PayPal and Apple Pay.", "") + "<a href='/gift-cards'>E-Gift Card</a> <a href='/gift-card-balance'>Gift Card Balance</a>"
    signals = run("www.acme-outdoor.example", page("Acme", "<p>Shop now.</p>" + products(4, "$120.00", "$96.00"), footer))
    assert "shop_untraceable_payment" not in codes(signals)


def test_a_shop_that_accepts_crypto_alongside_cards_is_fine():
    footer = LEGIT_FOOTER.replace("Apple Pay.", "Apple Pay, and Bitcoin at checkout.")
    assert "shop_untraceable_payment" not in codes(run("www.acme-outdoor.example", page("Acme", products(4, "$120.00", "$96.00"), footer)))


def test_a_few_crossed_out_prices_and_a_countdown_are_not_a_warning_by_themselves():
    body = "<p>Ends soon! Flash sale.</p>" + products(3, "$100.00", "$25.00")
    signals = run("www.acme-outdoor.example", page("Acme", body))
    assert "shop_extreme_discount" not in codes(signals)
    assert strongest(signals) <= Severity.LOW


def test_a_page_that_is_not_a_shop_is_ignored_even_if_it_talks_about_discounts_and_bank_transfers():
    html = ("<html><head><title>How to spot a scam</title></head><body><p>Scammers advertise 90% off, ask for payment by bank transfer only, "
            "and hide their contact details. Never pay by Bitcoin.</p></body></html>")
    assert run("news.example", html) == []


def test_a_page_built_by_scripts_is_not_accused_of_hiding_its_contact_details():
    html = ('<html><head><title>Shop</title><script src="https://cdn.shopify.com/s/files/x.js"></script></head>'
            '<body><div id="app"></div><button>Add to cart</button></body></html>')
    found = codes(run("www.thin-shop.example", html))
    assert "shop_page_not_fully_readable" in found
    assert not ({"shop_no_contact_details", "shop_no_policies", "shop_untraceable_payment"} & found)


# ------------------------------------------------------------------------------ the individual signals

def test_the_word_apple_inside_another_word_is_not_the_brand():
    body = "<p>Fresh from the orchard: up to 80% off pineapples this week.</p>" + products(6, "$10.00", "$2.00")
    for host, title in (("pineapple-shop.com", "Pineapple Shop"), ("appleseed-orchard.com", "Appleseed Orchard")):
        assert "shop_brand_discount_unofficial" not in codes(run(host, page(title, body, FAKE_FOOTER)))


def test_a_brands_own_site_and_subdomains_are_never_flagged():
    body = "<p>Up to 70% off select styles.</p>" + products(8, "$120.00", "$36.00")
    for host in ("www.nike.com", "store.nike.com"):
        assert "shop_brand_discount_unofficial" not in codes(run(host, page("Nike. Just Do It.", body, LEGIT_FOOTER)))


@pytest.mark.parametrize("host", ["nike-outlet.shop", "nikeshoessale.store", "official-nike-deals.top", "nike2026.online"])
def test_a_brand_on_an_unofficial_bargain_domain_is_flagged(host):
    body = "<p>Up to 75% off!</p>" + products(6, "$150.00", "$39.00")
    assert "shop_brand_discount_unofficial" in codes(run(host, page("Sneakers", body, FAKE_FOOTER)))


def test_prices_are_not_mistaken_for_phone_numbers():
    # Regression: "199.99 249.99 299.99" looked like a phone number, which hid the missing contact details.
    body = "<p>Shop</p>" + "".join(f"<p>{p}</p>" for p in ("$199.99", "$249.99", "$299.99")) + "<button>Add to cart</button>"
    footer = "<footer>" + "Terms of service. Privacy policy. Returns. Shipping. " * 12 + "</footer>"
    assert "shop_no_contact_details" in codes(run("www.example-store.example", page("Store", body, footer)))


def test_only_a_free_mail_address_is_noted_but_a_phone_number_alongside_it_is_fine():
    only = "<footer>" + "Returns Shipping Terms Privacy. " * 20 + "Email: bestdeals4u@gmail.com</footer>"
    assert "shop_free_mail_contact" in codes(run("www.example-store.example", page("Store", products(4, "$50.00", "$40.00"), only)))
    both = only.replace("Email:", "Call +65 6123 4567. Email:")
    assert "shop_free_mail_contact" not in codes(run("www.example-store.example", page("Store", products(4, "$50.00", "$40.00"), both)))


def test_a_contact_page_link_without_details_is_only_a_low_note():
    footer = "<footer><a href='/contact'>Contact</a> <a href='/returns'>Returns</a> <a href='/terms'>Terms</a>" + " padding text" * 60 + "</footer>"
    signal = next(s for s in run("www.example-store.example", page("Store", products(4, "$50.00", "$40.00"), footer)) if s.code == "shop_no_contact_details")
    assert signal.severity == Severity.LOW and signal.evidence["contact_page_linked"] is True


def test_a_closing_down_sale_and_a_deep_discount_count_as_one_kind_of_flag():
    body = "<h2>Closing down sale - everything must go! 80% off!</h2>" + products(6, "$100.00", "$20.00")
    signals = run("www.example-store.example", page("Store", body))
    assert {"shop_closing_down_sale", "shop_extreme_discount"} <= codes(signals)
    assert "fake_shop_pattern" not in codes(signals)


def test_a_young_domain_reported_by_whois_is_carried_into_the_shop_picture():
    prior = [Signal("whois", "young_domain", Severity.MEDIUM, "registered 9 days ago", {"age_days": 9})]
    body = "<p>Sale ends in 01:00:00! 80% off!</p>" + products(6, "$100.00", "$20.00")
    signals = run("www.example-store.example", page("Store", body, FAKE_FOOTER), prior)
    new_domain = next(s for s in signals if s.code == "shop_new_domain")
    assert new_domain.severity == Severity.LOW  # WHOIS already reports it as MEDIUM; this must not count twice


# ---------------------------------------------------------------------------- the overall pattern

def test_two_kinds_of_flag_do_not_make_a_pattern_three_do():
    two = "<p>80% off everything!</p>" + products(6, "$100.00", "$20.00")
    assert "fake_shop_pattern" not in codes(run("www.example-store.example", page("Store", two, LEGIT_FOOTER.replace("Contact us", "").replace("hello@acme-outdoor.example", "").replace("+65 6123 4567", "").replace("12 Robinson Road", ""))))
    three = two + "<p>Sale ends in 01:00:00. Hurry, only 2 left.</p>"
    signals = run("www.example-store.example", page("Store", three, FAKE_FOOTER))
    pattern = next(s for s in signals if s.code == "fake_shop_pattern")
    assert pattern.severity == Severity.HIGH and pattern.evidence["count"] >= 3


def test_a_shop_with_a_high_pattern_is_rated_suspicious_not_malicious():
    body = "<p>80% off!</p>" + products(6, "$100.00", "$20.00") + "<p>Sale ends in 01:00:00.</p>"
    signals = run("www.example-store.example", page("Store", body, FAKE_FOOTER))
    assert aggregator.rate(signals).verdict == "Suspicious"


# ------------------------------------------------------------------------------------------ robustness

@pytest.mark.parametrize("html", ["", "<html></html>", "<<<>>>", "<div>" * 5000, "\x00\x01" * 1000, "<html><body>" + "<p>x</p>" * 200000],
                         ids=["empty", "bare_html", "junk_tags", "deep_nesting", "control_chars", "many_paragraphs"])
def test_odd_and_hostile_pages_do_not_crash_or_stall(html):
    started = time.monotonic()
    assert isinstance(shop_check.check("example.com", "t", "text " * 100, html), list)
    assert time.monotonic() - started < 10


def test_missing_text_and_title_are_handled():
    assert shop_check.check("example.com", None, "", "") == []
    assert shop_check.check("example.com", None, None, None) == []

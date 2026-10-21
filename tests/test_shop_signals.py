"""Lightweight, gated shop-structural checks for the general URL checker (usi/content/shop_signals.py).

Why this exists: the embedding classifier's 'scam-shop' category cannot discriminate real shops from scam
shops. A margin-based rescoring was tested live and falsified on 2026-10-21 (target.com's margin exceeded
the weakest synthetic scam sample's). The only reliable fix is the structural checks usi/shop/ already has
for the dedicated shop checker, reused here in a bounded, gated way.

A single-page-only version was tried first and REJECTED: live-tested against 10 real major retailers, it
false-positived shop_no_contact on 7 of them, because contact details live on a separate /contact page, not
the homepage. This module always fetches a few extra, same-site pages (pages.pick_extra_pages) once gated -
the tests below mock that fetch rather than hitting the network, but the real multi-page behavior was
verified live (see memory/project notes) before this was written this way."""
from unittest import mock

from usi.config import Config
from usi.content import shop_signals
from usi.models import Severity
from usi.shop import pages

cfg = Config()


def page(html, url="http://example-shop.test/"):
    return pages.parse_page(url, html)


# --- looks_like_shop() gate ---

def test_price_and_cta_together_gates():
    html = "<html><body>Buy now! Only $19.99 add to cart today!</body></html>"
    assert shop_signals.looks_like_shop(html, html) is True


def test_price_alone_does_not_gate():
    html = "<html><body>This news article discusses the price of $19.99 oil futures.</body></html>"
    assert shop_signals.looks_like_shop(html, html) is False


def test_cta_alone_does_not_gate():
    html = "<html><body>Add to cart is a common UI pattern discussed in this design article.</body></html>"
    assert shop_signals.looks_like_shop(html, html) is False


def test_neither_does_not_gate():
    html = "<html><body>Welcome to our blog about cooking and recipes.</body></html>"
    assert shop_signals.looks_like_shop(html, html) is False


def test_a_recognised_shop_platform_gates_without_needing_price_or_cta():
    html = "<html><body><script src='https://cdn.shopify.com/s/files/x.js'></script></body></html>"
    assert shop_signals.looks_like_shop(html, html) is True


# --- check(): structural signals ---

REALISTIC_SCAM_HTML = """
<html><head><title>Mega Sale</title></head><body>
<nav><a href="/">Home</a><a href="/shop">Shop</a></nav>
<h1>MEGA CLEARANCE 90% OFF everything!</h1>
<div class="product"><span>Jacket -85%</span><span>$19.99</span><button>add to cart</button></div>
<div class="product"><span>Boots -90%</span><span>$12.99</span><button>add to cart</button></div>
<div class="product"><span>Bag -88%</span><span>$9.99</span><button>add to cart</button></div>
<div class="product"><span>Watch -92%</span><span>$14.99</span><button>add to cart</button></div>
<div class="product"><span>Shoes -87%</span><span>$11.99</span><button>add to cart</button></div>
<div class="product"><span>Scarf -95%</span><span>$4.99</span><button>add to cart</button></div>
<p>Payment by Western Union, wire transfer or cryptocurrency only. Buy now before the timer runs out!</p>
<p>Checkout now and save big. Shop now, limited stock!</p>
</body></html>
"""


def test_a_realistic_scam_shop_page_crosses_the_two_medium_cooccurrence_threshold():
    # 2+ MEDIUM signals is exactly what usi/verdict/aggregator.py promotes to "Suspicious" on its own.
    with mock.patch.object(pages.Fetcher, "page", return_value=None):
        signals = shop_signals.check("http://fake-scam-shop.test/", "fake-scam-shop.test",
                                     REALISTIC_SCAM_HTML, [], cfg)
    medium_plus = [s for s in signals if s.severity >= Severity.MEDIUM]
    assert len(medium_plus) >= 2
    assert {"shop_deep_discounts", "shop_payment_irreversible", "shop_prepayment_only"} & {s.code for s in medium_plus}


def test_discount_and_payment_signals_run_even_on_an_unreadable_short_page():
    # Regression: an early version early-returned on `not pages.is_readable(main)`, silently skipping
    # discount/payment detection on any short page (nav + a few product divs isn't much text) - those
    # checks are pure text-pattern matches and need no "readability" at all. Only the contact-MISSING
    # inference should be gated on readability (an apparent absence proves nothing on a script-built page).
    minimal_html = "<html><body>" + "".join(
        f'<span>-{p}%</span>' for p in (85, 86, 87, 88, 89, 90)
    ) + " Buy now! $9.99 Pay by wire transfer only, no card accepted. add to cart</body></html>"
    assert pages.is_readable(page(minimal_html)) is False  # confirms the test is exercising the gap
    with mock.patch.object(pages.Fetcher, "page", return_value=None):
        signals = shop_signals.check("http://x.test/", "x.test", minimal_html, [], cfg)
    codes = {s.code for s in signals}
    assert "shop_deep_discounts" in codes or "shop_prepayment_only" in codes


def test_contact_missing_is_not_inferred_on_an_unreadable_page():
    minimal_html = "<html><body>Buy now $9.99 add to cart</body></html>"
    assert pages.is_readable(page(minimal_html)) is False
    with mock.patch.object(pages.Fetcher, "page", return_value=None):
        signals = shop_signals.check("http://x.test/", "x.test", minimal_html, [], cfg)
    assert "shop_no_contact" not in {s.code for s in signals}


# --- real-site false-positive regression guards (the actual finding that shaped this module) ---

def test_a_readable_page_with_real_contact_info_on_an_extra_page_does_not_flag_no_contact():
    main_html = (
        "<html><body><nav><a href='/contact'>Contact Us</a></nav>"
        "<p>Welcome to our store. Buy now! $25.00 add to cart.</p>" + "x" * 300 + "</body></html>"
    )
    contact_page = pages.parse_page("http://example-shop.test/contact",
                                    "<html><body>Email: support@example-shop.test, Phone: +1 555 0100, "
                                    "123 Main St, Springfield</body></html>")
    with mock.patch.object(pages.Fetcher, "page", return_value=contact_page):
        signals = shop_signals.check("http://example-shop.test/", "example-shop.test", main_html, [], cfg)
    assert "shop_no_contact" not in {s.code for s in signals}


def test_a_single_weak_signal_alone_never_reaches_the_cooccurrence_threshold():
    # One MEDIUM (e.g. no contact found anywhere) must not alone look "Suspicious" - that's the
    # aggregator's job via MEDIUM_COOCCURRENCE_THRESHOLD, not this module's; confirm it only ever
    # contributes that one signal for an otherwise ordinary readable page.
    main_html = (
        "<html><body><nav><a href='/'>Home</a></nav>"
        "<p>Welcome to our store. Buy now! $25.00, pay by card. add to cart.</p>" + "x" * 300 + "</body></html>"
    )
    with mock.patch.object(pages.Fetcher, "page", return_value=None):
        signals = shop_signals.check("http://example-shop.test/", "example-shop.test", main_html, [], cfg)
    medium_plus = [s for s in signals if s.severity >= Severity.MEDIUM]
    assert len(medium_plus) <= 1

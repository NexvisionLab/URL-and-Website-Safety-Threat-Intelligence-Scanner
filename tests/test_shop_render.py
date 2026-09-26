"""Rendering pieces that don't need a browser: the address guard, choosing a renderer, the remote
client, and comparing the desktop view with the phone-from-Facebook view."""
import socket

import pytest

from usi.models import Severity
from usi.shop import browser, pages, render

STOREFRONT = "<html><head><title>Walking Pads</title></head><body>" + "".join(
    f'<a href="/products/p{i}">Product {i}</a>' for i in range(20)) + "<p>" + "Great deals on walking pads. " * 30 + "</p></body></html>"
NOT_FOUND = "<html><head><title>404 Not Found</title></head><body>Not Found</body></html>"
CHALLENGE = "<html><head><title>Just a moment...</title></head><body>Enable JavaScript and cookies to continue</body></html>"


def view(profile, status, html, url="https://shop.example/"):
    return browser.Rendered(ok=True, profile=profile, status=status, final_url=url, title="", html=html)


def resolver(mapping):
    def resolve(host, port, type=None):
        if host not in mapping:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0)) for ip in mapping[host]]
    return resolve


def test_address_guard_refuses_internal_and_odd_targets():
    guard = browser.AddressGuard(resolver({"shop.example": ["93.184.216.34"], "evil.example": ["10.0.0.5"],
                                           "mixed.example": ["93.184.216.34", "127.0.0.1"]}))
    assert guard.allowed("https://shop.example/cart")
    assert not guard.allowed("http://evil.example/")
    assert not guard.allowed("http://mixed.example/")          # one private answer is enough to refuse
    assert not guard.allowed("http://169.254.169.254/latest/meta-data/")
    assert not guard.allowed("http://[::1]:8080/")
    assert not guard.allowed("file:///etc/passwd")
    assert not guard.allowed("https://unknown.example/")        # can't resolve: nothing to go on
    assert guard.allowed("data:text/plain,hello")


def test_render_refuses_before_starting_a_browser():
    guard = browser.AddressGuard(resolver({"evil.example": ["192.168.1.1"]}))
    r = browser.render("http://evil.example/", "desktop", guard=guard)
    assert not r.ok and "cannot be checked" in r.error
    with pytest.raises(ValueError):
        browser.render("http://evil.example/", "tablet", guard=guard)


def test_cloaked_storefront_is_high():
    sig = render.compare_views(view("desktop", 404, NOT_FOUND), view("phone_facebook", 200, STOREFRONT))
    assert [s.code for s in sig] == ["shop_cloaked_for_ads"] and sig[0].severity == Severity.HIGH


def test_blocked_desktop_is_not_called_cloaking():
    # A bot check on the desktop view is ambiguous, not evidence of cloaking.
    assert render.compare_views(view("desktop", 403, CHALLENGE), view("phone_facebook", 200, STOREFRONT)) == []


def test_failed_desktop_render_says_nothing():
    failed = browser.Rendered(ok=False, profile="desktop", error="timeout")
    assert [s.code for s in render.compare_views(failed, view("phone_facebook", 200, STOREFRONT))] == ["shop_views_consistent"]


def test_phone_sent_elsewhere_is_medium():
    sig = render.compare_views(view("desktop", 200, STOREFRONT, "https://walking-pads.com/"),
                               view("phone_facebook", 200, STOREFRONT, "https://other-store.com/landing"))
    assert sig[0].code == "shop_redirects_ad_visitors" and sig[0].evidence["phone_site"] == "other-store.com"


def test_same_view_is_consistent_and_unreadable_phone_view_is_ignored():
    assert [s.code for s in render.compare_views(view("desktop", 200, STOREFRONT), view("phone_facebook", 200, STOREFRONT))] \
        == ["shop_views_consistent"]
    assert render.compare_views(view("desktop", 404, NOT_FOUND), view("phone_facebook", 200, NOT_FOUND)) == []


def test_as_page_only_accepts_a_real_page():
    assert render.as_page(view("desktop", 200, STOREFRONT)) is not None
    assert render.as_page(view("desktop", 403, STOREFRONT)) is None
    assert render.as_page(view("desktop", 200, CHALLENGE)) is None
    assert render.as_page(browser.Rendered(ok=False, profile="desktop")) is None


def test_renderer_choice(monkeypatch):
    monkeypatch.delenv("USI_RENDER_URL", raising=False)
    monkeypatch.delenv("USI_RENDER_LOCAL", raising=False)
    assert render.get_renderer() is None
    monkeypatch.setenv("USI_RENDER_URL", "http://127.0.0.1:8796/")
    assert isinstance(render.get_renderer(), render.RemoteRenderer)
    monkeypatch.delenv("USI_RENDER_URL")
    monkeypatch.setenv("USI_RENDER_LOCAL", "1")
    monkeypatch.setattr(browser, "available", lambda: False)
    assert render.get_renderer() is None  # asked for, but no browser installed


def test_remote_renderer(monkeypatch):
    class Resp:
        status_code = 200

        def json(self):
            return {"ok": True, "profile": "desktop", "status": 200, "final_url": "https://shop.example/",
                    "title": "Shop", "html": "<html></html>", "unexpected": "ignored"}
    seen = {}

    def post(url, json, timeout):
        seen.update(url=url, body=json)
        return Resp()
    monkeypatch.setattr(render.requests, "post", post)
    r = render.RemoteRenderer("http://127.0.0.1:8796/").render("https://shop.example/", "desktop")
    assert r.ok and r.status == 200 and seen["url"] == "http://127.0.0.1:8796/render"
    monkeypatch.setattr(render.requests, "post", lambda *a, **k: (_ for _ in ()).throw(render.requests.ConnectionError()))
    assert not render.RemoteRenderer("http://127.0.0.1:8796").render("https://shop.example/", "desktop").ok


def test_product_links_are_picked_by_path():
    page = pages.parse_page("https://shop.example/", '<a href="/products/blue-mat">Blue mat</a>'
                            '<a href="/collections/products">Products</a><a href="/pages/contact">Contact</a>')
    kinds = pages.classify_links(page, "shop.example")
    assert kinds["product"] == ["https://shop.example/products/blue-mat"]
    assert "https://shop.example/products/blue-mat" in pages.pick_extra_pages(kinds, page.url)

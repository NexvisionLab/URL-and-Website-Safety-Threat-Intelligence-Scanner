import pytest

from usi.models import Severity
from usi.shop import fingerprint, pages

HTML = """<html><head>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-AB12CD34EF"></script>
<script>(function(w,d,s,l,i){})(window,document,'script','dataLayer','GTM-K9X2PQ7');</script>
<script>fbq('init', '1234567890123456'); ttq.load('C4ABCDEFGH1234567890');</script>
<script>var Shopify = {shop: "cheap-pads-store.myshopify.com"}; // cdn from shops.myshopify.com</script>
</head><body>Welcome</body></html>"""


@pytest.fixture(autouse=True)
def network_db(monkeypatch, tmp_path):
    monkeypatch.setenv(fingerprint.DB_ENV, str(tmp_path / "network.sqlite3"))


def test_extracts_tracking_ids_store_contacts_and_non_platform_servers():
    page = pages.Page(url="https://a.example/", html=HTML, text="")
    contacts = {"emails": ["help@cheappads.shop", "support@shopify.com"], "phones": ["+65 6123 4567"], "addresses": []}
    prints = fingerprint.extract([page], contacts, ["201511638H"], ["23.227.38.32", "104.16.1.1", "203.0.113.9"])
    assert ("google_analytics", "G-AB12CD34EF") in prints
    assert ("google_tag_manager", "GTM-K9X2PQ7") in prints
    assert ("facebook_pixel", "1234567890123456") in prints
    assert ("tiktok_pixel", "C4ABCDEFGH1234567890") in prints
    assert ("shopify_store", "cheap-pads-store") in prints
    assert ("shopify_store", "shops") not in prints                    # platform hostname, not a store
    assert ("email", "help@cheappads.shop") in prints
    assert ("email", "support@shopify.com") not in prints              # platform contact, shared by everyone
    assert ("phone", "561234567") in prints
    assert ("uen", "201511638H") in prints
    assert ("server", "203.0.113.9") in prints
    assert ("server", "23.227.38.32") not in prints                    # Shopify
    assert ("server", "104.16.1.1") not in prints                      # Cloudflare


def test_phone_numbers_match_across_formats():
    a = fingerprint.extract([], {"phones": ["+65 6123 4567"]}, [], [])
    b = fingerprint.extract([], {"phones": ["6123-4567"]}, [], [])
    assert a & b or {p[1][-8:] for p in a} == {p[1][-8:] for p in b}


def test_match_counts_other_shops_and_their_pre_network_bands():
    ga = {("google_analytics", "G-AB12CD34EF")}
    fingerprint.remember("fake-one.shop", "High", ga)
    fingerprint.remember("fake-two.shop", "High", ga | {("email", "x@y.shop")})
    fingerprint.remember("other.com", "Low", ga)
    m = fingerprint.match("new-shop.shop", ga)
    assert m == {"google_analytics": {"shops": 3, "high": 2, "elevated": 0}}
    assert fingerprint.match("fake-one.shop", ga)["google_analytics"]["shops"] == 2  # never matches itself


def test_remember_replaces_a_shops_old_fingerprints():
    fingerprint.remember("a.shop", "Low", {("uen", "1")})
    fingerprint.remember("a.shop", "High", {("uen", "2")})
    assert fingerprint.match("b.shop", {("uen", "1")}) == {}
    assert fingerprint.match("b.shop", {("uen", "2")})["uen"]["high"] == 1


def test_signals():
    high = {"facebook_pixel": {"shops": 5, "high": 4, "elevated": 0}}
    s = fingerprint.signals(high)
    assert s[0].code == "shop_network_high_risk" and s[0].severity == Severity.MEDIUM and "Facebook pixel" in s[0].message
    copied = fingerprint.signals(high, established_and_clean=True)
    assert copied[0].code == "shop_network_copied" and copied[0].severity == Severity.INFO
    group = fingerprint.signals({"uen": {"shops": 4, "high": 0, "elevated": 1}})
    assert group[0].code == "shop_network" and group[0].severity == Severity.LOW
    assert fingerprint.signals({"uen": {"shops": 1, "high": 0, "elevated": 0}})[0].severity == Severity.INFO
    assert fingerprint.signals({}) == []


def test_unreadable_database_is_quietly_skipped(monkeypatch, tmp_path):
    monkeypatch.setenv(fingerprint.DB_ENV, str(tmp_path))  # a directory, not a file
    assert fingerprint.match("a.shop", {("uen", "1")}) == {}
    fingerprint.remember("a.shop", "Low", {("uen", "1")})  # must not raise

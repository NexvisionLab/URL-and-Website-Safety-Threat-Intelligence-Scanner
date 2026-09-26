from datetime import datetime, timedelta, timezone

from usi.models import Severity
from usi.shop import catalogue

NOW = datetime(2026, 9, 25, tzinfo=timezone.utc)


def _shopify(n, price, was, days_old):
    created = (NOW - timedelta(days=days_old)).isoformat()
    return {"products": [
        {"created_at": created, "variants": [{"price": str(price), "compare_at_price": str(was) if was else None}]}
        for _ in range(n)]}


def test_detect_platform():
    assert catalogue.detect_platform('<script src="//cdn.shopify.com/s/x.js">') == "shopify"
    assert catalogue.detect_platform('<link href="/wp-content/plugins/woocommerce/a.css">') == "woocommerce"
    assert catalogue.detect_platform("<html></html>") is None


def test_feed_urls():
    assert catalogue.feed_url("shopify", "https://s.example/collections/x") == "https://s.example/products.json?limit=250"
    assert (catalogue.feed_url("woocommerce", "https://s.example/")
            == "https://s.example/wp-json/wc/store/v1/products?per_page=100")


def test_parse_shopify_uses_cheapest_variant_and_skips_junk():
    data = {"products": [
        {"created_at": "2026-09-01T00:00:00Z", "variants": [{"price": "30", "compare_at_price": "90"},
                                                            {"price": "20", "compare_at_price": "80"}]},
        {"variants": [{"price": "abc"}]}, "junk", {"variants": None}]}
    items = catalogue.parse_shopify(data)
    assert len(items) == 1 and items[0]["price"] == 20 and items[0]["was"] == 80


def test_parse_woocommerce_minor_units():
    data = [{"prices": {"price": "1999", "regular_price": "5999"}}, {"prices": {"price": "500", "regular_price": "500"}},
            {"no": "prices"}]
    items = catalogue.parse_woocommerce(data)
    assert [round(1 - i["price"] / i["was"], 2) for i in items] == [0.67, 0.0]


def test_deep_catalogue_wide_discount_is_flagged():
    facts = catalogue.summarise(catalogue.parse_shopify(_shopify(20, 30, 100, 400)), now=NOW)
    deep = [s for s in catalogue.signals_from_feed(facts, "shopify") if s.code == "shop_deep_discounts"]
    assert deep and deep[0].severity == Severity.MEDIUM and "70%" in deep[0].message


def test_everything_on_sale_is_flagged():
    facts = catalogue.summarise(catalogue.parse_shopify(_shopify(40, 61, 100, 400)), now=NOW)
    deep = [s for s in catalogue.signals_from_feed(facts, "shopify") if s.code == "shop_deep_discounts"]
    assert deep and deep[0].evidence["pattern"] == "everything_on_sale"


def test_a_big_sale_with_small_markdowns_is_not_flagged():
    # Like a genuine electronics retailer measured on 2026-09-25: 84% of products on sale, typically 10% off.
    items = (catalogue.parse_shopify(_shopify(42, 90, 100, 400))
             + catalogue.parse_shopify(_shopify(8, 100, None, 400)))
    assert "shop_deep_discounts" not in {s.code for s in catalogue.signals_from_feed(catalogue.summarise(items, now=NOW), "shopify")}


def test_ordinary_sale_is_not_flagged():
    items = (catalogue.parse_shopify(_shopify(6, 80, 100, 400))
             + catalogue.parse_shopify(_shopify(14, 100, None, 400)))
    sigs = catalogue.signals_from_feed(catalogue.summarise(items, now=NOW), "shopify")
    assert [s.code for s in sigs] == ["shop_catalogue"]


def test_small_catalogue_is_not_judged():
    facts = catalogue.summarise(catalogue.parse_shopify(_shopify(3, 10, 100, 1)), now=NOW)
    assert "shop_deep_discounts" not in {s.code for s in catalogue.signals_from_feed(facts, "shopify")}


def _new(facts, age):
    return [s for s in catalogue.signals_from_feed(facts, "shopify", age) if s.code == "shop_catalogue_new"]


def test_new_catalogue_weighs_more_when_the_domain_age_is_unknown_or_young():
    facts = catalogue.summarise(catalogue.parse_shopify(_shopify(12, 100, None, 9)), now=NOW)
    assert facts["first_listed_days"] == 9
    assert _new(facts, None)[0].severity == Severity.MEDIUM   # .de/.at: no registration date published
    assert _new(facts, 200)[0].severity == Severity.MEDIUM
    assert _new(facts, 3000)[0].severity == Severity.LOW      # an old shop that moved platform


def test_badges():
    text = "SALE -70% -65% jetzt 80% Rabatt, save 60% and 70% off. 100% cotton, 24/7, 2-3 days, v1.5%"
    assert sorted(catalogue.badge_discounts(text)) == [60, 65, 70, 70, 80]
    assert catalogue.signals_from_badges([70, 65, 80, 60, 70])[0].code == "shop_deep_discounts"
    assert catalogue.signals_from_badges([70, 65]) == []
    assert catalogue.signals_from_badges([10, 20, 15, 10, 30]) == []

import pytest

from usi.shop import platforms


@pytest.mark.parametrize("url,pid,ticks", [
    ("https://shopee.sg/some-product-i.1.2", "shopee", 4),
    ("https://www.lazada.sg/products/x.html", "lazada", 4),
    ("https://www.amazon.sg/dp/B000", "amazon", 4),
    ("https://www.carousell.sg/p/nintendo-switch-123/", "carousell", 2),
    ("https://www.facebook.com/marketplace/item/123/", "facebook_marketplace", 1),
    ("https://www.tiktok.com/view/product/1729", "tiktok_shop", 4),
])
def test_rated_platforms(url, pid, ticks):
    p = platforms.identify(url)
    assert p["id"] == pid and p["mha_ticks"] == ticks
    assert p["mha_ratings_url"] == platforms.RATINGS_URL
    assert p["advice"]


def test_foreign_storefront_does_not_borrow_the_sg_rating():
    p = platforms.identify("https://www.amazon.com/dp/B000")
    assert p["id"] == "amazon" and p["mha_ticks"] is None and p["mha_ratings_url"] is None


def test_facebook_page_is_social_not_marketplace():
    p = platforms.identify("https://www.facebook.com/SomeShopPage")
    assert p["id"] == "facebook" and p["kind"] == "social" and p["mha_ticks"] is None


@pytest.mark.parametrize("url,kind", [("https://t.me/cheapdeals", "chat"), ("wa.me/6591234567", "chat"),
                                      ("https://www.instagram.com/shop.sg/", "social")])
def test_chat_and_social(url, kind):
    assert platforms.identify(url)["kind"] == kind


@pytest.mark.parametrize("url", ["https://courts.com.sg/", "https://notshopee.sg/", "https://shopee-sale.shop/"])
def test_independent_sites_are_not_platforms(url):
    assert platforms.identify(url) is None

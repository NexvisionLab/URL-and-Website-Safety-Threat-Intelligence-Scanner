import pytest

from usi.shop import brands

BRANDS = brands.load()


@pytest.mark.parametrize("host,brand", [
    ("currentbodyaustria.com", "CurrentBody"),
    ("eu-segway.com", "Segway"),
    ("nike-outlet.shop", "Nike"),
    ("nikeoutlet.shop", "Nike"),
    ("www.dysonsingapore.com", "Dyson"),
    ("sale.harveynorman-sg.store", "Harvey Norman"),
])
def test_brand_used_in_address(host, brand):
    assert brands.brand_in_address(host, BRANDS)["name"] == brand


@pytest.mark.parametrize("host", [
    "www.nike.com", "dyson.com.sg", "shop.lego.com",      # the brands' own sites
    "snikers.com", "legolasfans.com", "unikebikes.shop",  # the name only as part of another word
    "walkingmats.com",
])
def test_no_brand_match(host):
    assert brands.brand_in_address(host, BRANDS) is None


def test_official_store_claim():
    sig = brands.signals("bestdeals.shop", "Official Dyson Store - 70% off", "", BRANDS)
    assert [s.code for s in sig] == ["shop_official_claim"]
    assert sig[0].evidence["real_domains"][0] == "dyson.com"


def test_official_claim_on_the_real_site_is_fine():
    assert brands.signals("www.dyson.com.sg", "Official Dyson Store", "", BRANDS) == []


def test_address_match_names_the_real_site():
    sig = brands.signals("eu-segway.com", "", "", BRANDS)
    assert sig[0].code == "shop_brand_in_address" and sig[0].evidence["real_domains"] == ["segway.com"]

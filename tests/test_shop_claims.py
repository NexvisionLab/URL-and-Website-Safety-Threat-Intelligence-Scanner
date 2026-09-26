from usi.models import Severity
from usi.shop import claims


def test_clean_drops_unknown_values():
    assert claims.clean({"payment_requested": "PayNow", "advertised_on": "myspace", "price_seen": "abc",
                         "usual_price": -5}) == {"payment_requested": "paynow"}
    assert claims.clean(None) == {}


def test_irreversible_payment_is_high():
    sig = claims.signals({"payment_requested": "gift_card"})
    assert sig[0].code == "claim_payment_irreversible" and sig[0].severity == Severity.HIGH


def test_transfer_is_medium():
    assert claims.signals({"payment_requested": "bank_transfer"})[0].severity == Severity.MEDIUM


def test_card_payment_is_not_a_finding():
    assert claims.signals({"payment_requested": "card"}) == []


def test_deep_claimed_discount():
    sig = claims.signals({"price_seen": 40, "usual_price": 200})
    assert sig[0].code == "claim_deep_discount" and sig[0].evidence["discount_pct"] == 80
    assert claims.signals({"price_seen": 150, "usual_price": 200}) == []


def test_advert_is_context_only():
    assert claims.signals({"advertised_on": "instagram"})[0].severity == Severity.INFO

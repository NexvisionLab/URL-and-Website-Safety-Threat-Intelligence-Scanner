from usi.shop import payment


def codes(found):
    return [s.code for s in payment.signals(found)]


def test_card_icons_in_html_count():
    found = payment.detect(['<svg aria-labelledby="pi-visa"><title>Visa</title></svg><img alt="PayPal">'], [""])
    assert found["reversible"] == ["card", "PayPal"]
    assert codes(found) == ["shop_payment_methods"]


def test_transfer_only_is_flagged():
    found = payment.detect([""], ["Zahlung per Vorkasse. Bitte den Betrag vorab bezahlen."])
    assert found["transfer"] == ["bank transfer"] and not found["reversible"]
    assert codes(found) == ["shop_prepayment_only"]


def test_paynow_only_is_flagged():
    assert codes(payment.detect([""], ["Pay via PayNow to 9123 4567 after ordering"])) == ["shop_prepayment_only"]


def test_crypto_is_flagged_even_with_cards():
    assert codes(payment.detect([""], ["We accept Visa, Mastercard and Bitcoin (BTC)."])) == ["shop_payment_irreversible"]


def test_bank_transfer_alongside_cards_is_fine():
    assert codes(payment.detect([""], ["Visa, PayPal, or bank transfer"])) == ["shop_payment_methods"]


def test_nothing_shown_is_info_not_a_finding():
    sig = payment.signals(payment.detect([""], ["Welcome to our shop"]))
    assert len(sig) == 1 and sig[0].severity.name == "INFO" and "No payment methods" in sig[0].message

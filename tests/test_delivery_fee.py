from usi.content import delivery_fee


def test_english_held_plus_fee_flagged():
    sig = delivery_fee.check(
        "Your parcel is held at customs. Pay the customs fee to release your delivery."
    )
    assert sig is not None
    assert sig.code == "fake_delivery_fee_scam"


def test_portuguese_correios_pattern_flagged():
    sig = delivery_fee.check(
        "Seu pacote esta retido na alfandega. Pague a taxa alfandegaria para liberar a entrega."
    )
    assert sig is not None
    assert sig.code == "fake_delivery_fee_scam"


def test_french_colissimo_pattern_flagged():
    sig = delivery_fee.check(
        "Votre colis est bloque en douane. Payez les frais de douane pour le liberer."
    )
    assert sig is not None
    assert sig.code == "fake_delivery_fee_scam"


def test_german_pattern_flagged():
    sig = delivery_fee.check(
        "Ihr Paket wird zurueckgehalten. Bitte Zollgebuehr bezahlen um die Sendung freizugeben."
    )
    assert sig is not None
    assert sig.code == "fake_delivery_fee_scam"


def test_spanish_pattern_flagged():
    sig = delivery_fee.check(
        "Su paquete esta retenido en aduanas. Pagar la tarifa aduanera para continuar."
    )
    assert sig is not None
    assert sig.code == "fake_delivery_fee_scam"


def test_held_language_alone_is_weaker_signal():
    sig = delivery_fee.check("Your delivery is on hold, please contact support for details.")
    assert sig is not None
    assert sig.code == "delivery_fee_language_present"


def test_normal_shipping_notification_not_flagged():
    sig = delivery_fee.check("Your package has shipped and will arrive Tuesday. Track your order here.")
    assert sig is None


def test_empty_text_not_flagged():
    assert delivery_fee.check(None) is None
    assert delivery_fee.check("") is None


def test_toll_scam_with_authority_name_is_high_severity():
    sig = delivery_fee.check_toll(
        "You have an unpaid toll on your E-ZPass account. Pay now to avoid penalties."
    )
    assert sig is not None
    assert sig.code == "toll_scam_pattern"
    from usi.models import Severity
    assert sig.severity == Severity.HIGH
    assert sig.evidence["mentions_authority"] is True


def test_toll_scam_without_authority_name_is_medium_severity():
    sig = delivery_fee.check_toll("You have an outstanding toll balance. Pay before it is sent to collections.")
    assert sig is not None
    assert sig.code == "toll_scam_pattern"
    from usi.models import Severity
    assert sig.severity == Severity.MEDIUM
    assert sig.evidence["mentions_authority"] is False


def test_spanish_toll_scam_flagged():
    sig = delivery_fee.check_toll("Tiene un peaje pendiente en su cuenta SunPass. Pague ahora.")
    assert sig is not None
    assert sig.code == "toll_scam_pattern"


def test_sunpass_variant_names_recognized():
    sig = delivery_fee.check_toll("Your SunPass toll invoice is overdue.")
    assert sig is not None
    assert sig.evidence["mentions_authority"] is True


def test_normal_toll_page_not_flagged():
    sig = delivery_fee.check_toll("Learn how our electronic toll collection system works.")
    assert sig is None


def test_toll_empty_text_not_flagged():
    assert delivery_fee.check_toll(None) is None
    assert delivery_fee.check_toll("") is None

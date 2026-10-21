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


# --- scam-awareness pages (2026-10-21) ---
# darknyx.com's own Safety Guide quotes toll and parcel-fee scams as examples, and its own checker rated the
# site "Suspicious" because of them. Text below is the guide's real wording (trimmed), as the checker sees it.
SAFETY_GUIDE_TEXT = """
Spot a scam message. Most scams share the same red flags.
Unpaid toll or fine
Text message
"Final notice: unpaid road toll of $6.40. To avoid a $50 late fee and licence suspension, pay now at etoll-payments-us.com/pay"
A tiny amount for a bill you never received.
A threat that grows the longer you wait.
Toll and traffic offices use their own website or app, not a link in a text.
Do this Do not click. Look up the toll operator yourself and check your account there.
Fake delivery notice
Text message
"SingPost: your parcel is held at customs. Pay a $2.99 customs fee at sg-post-redeliver.xyz within 48 hours."
A small fee is how they get your card number.
Do this Open the courier's official app and enter your tracking number there.
Phishing messages copy real companies. A scam often uses a deadline. Scammers want you to act fast.
These are the red flags in every scam. Report the scam and do not click the link.
Never reply to a scam text, and block the phishing sender.
"""


def test_a_scam_awareness_page_quoting_toll_wording_is_informational_not_a_finding():
    from usi.models import Severity
    sig = delivery_fee.check_toll(SAFETY_GUIDE_TEXT)
    assert sig is not None
    assert sig.code == "toll_scam_wording_in_awareness_page"
    assert sig.severity == Severity.INFO


def test_a_scam_awareness_page_quoting_parcel_fee_wording_is_informational_not_a_finding():
    from usi.models import Severity
    sig = delivery_fee.check(SAFETY_GUIDE_TEXT)
    assert sig is not None
    assert sig.code == "delivery_fee_wording_in_awareness_page"
    assert sig.severity == Severity.INFO


def test_a_real_toll_scam_page_still_fires_with_no_awareness_language():
    from usi.models import Severity
    sig = delivery_fee.check_toll("Final notice: you have an unpaid toll on your E-ZPass account. Pay now to avoid a $50 late fee.")
    assert sig.code == "toll_scam_pattern"
    assert sig.severity == Severity.HIGH


def test_a_parcel_scam_that_copies_a_warning_footer_still_fires():
    # Lures copy the carrier's own "beware of scams" footer. A handful of those words must not switch the
    # check off: it takes variety AND volume, which only a page about scams has.
    sig = delivery_fee.check(
        "Your parcel is held at customs. Pay the customs fee to release your delivery. "
        "Beware of scams and phishing. Do not click links from others. Royal Mail will never ask for your password."
    )
    assert sig.code == "fake_delivery_fee_scam"


def test_many_mentions_of_a_single_awareness_word_do_not_count_as_an_awareness_page():
    text = "Unpaid toll on your account, pay now. " + "Scam alert! " * 10
    assert delivery_fee.check_toll(text).code == "toll_scam_pattern"


def test_few_mentions_of_several_awareness_words_do_not_count_either():
    text = "Unpaid toll on your account, pay now. This is not a scam or phishing. Red flags: none."
    assert delivery_fee.check_toll(text).code == "toll_scam_pattern"

from usi.models import Severity, Signal
from usi.shop import rules


def sig(code, severity=Severity.MEDIUM, source="shop_x"):
    return Signal(source=source, code=code, severity=severity, message=code)


def rate(shop, url=(), examined=True):
    band, fired = rules.rate(list(url), list(shop), examined)
    return band, [r["id"] for r in fired]


def test_nothing_found_is_low():
    assert rate([sig("shop_contact", Severity.INFO)]) == ("Low", [])


def test_page_not_examined_is_not_enough_information():
    assert rate([], examined=False) == ("Not enough information", [])


def test_single_warning_is_elevated():
    assert rate([sig("shop_domain_new")]) == ("Elevated", ["warning_sign"])


def test_new_shop_with_deep_discounts_is_high():
    band, ids = rate([sig("shop_domain_new"), sig("shop_deep_discounts")])
    assert band == "High" and "new_shop_deep_discounts" in ids


def test_new_catalogue_counts_as_new():
    band, ids = rate([sig("shop_catalogue_new", Severity.LOW), sig("shop_prepayment_only")])
    assert band == "High" and "new_shop_unprotected_payment" in ids


def test_brand_copy_with_discounts_is_high():
    band, ids = rate([sig("shop_brand_in_address"), sig("shop_deep_discounts")])
    assert band == "High" and "brand_copy_new_or_discounted" in ids


def test_url_lookalike_counts_as_brand_copy():
    band, ids = rate([sig("shop_domain_new")], url=[sig("typosquat_match", Severity.HIGH, source="typosquat")])
    assert band == "High" and "brand_copy_new_or_discounted" in ids


def test_invalid_registration_alone_is_high():
    assert rate([sig("shop_uen_not_found", Severity.HIGH)])[0] == "High"
    assert rate([sig("shop_uen_deregistered", Severity.HIGH)])[0] == "High"


def test_not_found_but_numbered_this_year_is_not_high():
    assert rate([sig("shop_uen_not_found", Severity.LOW)])[0] == "Low"


def test_irreversible_payment_request_is_high():
    assert "irreversible_payment_requested" in rate([sig("claim_payment_irreversible", Severity.HIGH, "shop_claims")])[1]


def test_three_minor_signs_are_elevated_two_are_not():
    minor = [sig("shop_contact_thin", Severity.LOW), sig("shop_no_policies", Severity.LOW),
             sig("shop_sg_no_uen", Severity.LOW)]
    assert rate(minor) == ("Elevated", ["several_minor_signs"])
    assert rate(minor[:2]) == ("Low", [])


def test_three_warnings_are_high():
    band, ids = rate([sig("shop_no_contact"), sig("shop_template_text"), sig("shop_payment_irreversible")])
    assert band == "High" and "several_warning_signs" in ids


def test_url_findings_carry_over():
    assert rate([], url=[sig("drainer_detected", Severity.CRITICAL, source="crypto_drainer")])[0] == "High"
    assert rate([], url=[sig("cross_domain_form_post", Severity.HIGH, source="fetch")])[0] == "Elevated"


def test_url_young_domain_is_not_double_counted():
    band, ids = rate([sig("shop_domain_new")], url=[sig("young_domain", Severity.MEDIUM, source="whois")])
    assert band == "Elevated" and ids == ["warning_sign"]


def test_new_certificate_counts_as_new():
    band, ids = rate([sig("shop_cert_new"), sig("shop_prepayment_only")])
    assert band == "High" and "new_shop_unprotected_payment" in ids


def test_random_name_on_new_shop_is_high_but_alone_is_minor():
    assert "random_name_new_shop" in rate([sig("shop_random_name", Severity.LOW), sig("shop_domain_new")])[1]
    assert rate([sig("shop_random_name", Severity.LOW)]) == ("Low", [])


def test_two_address_signs_on_a_blocked_page_are_elevated():
    signs = [sig("shop_domain_recent", Severity.LOW), sig("shop_random_name", Severity.LOW)]
    assert rate(signs, examined=False) == ("Elevated", ["blocked_page_address_signs"])
    assert rate(signs, examined=True) == ("Low", [])

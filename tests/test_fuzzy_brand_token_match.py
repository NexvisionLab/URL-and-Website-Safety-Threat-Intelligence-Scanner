"""Fuzzy brand-token match (2026-10-20): a brand name misspelled by one typo-shaped edit, embedded as its
own token in a longer free-hosting host. Documented real miss from the 2026-09-27 OpenPhish sample:
not-start-eng-trezr.pages.dev for Trezor ('trezr' = 'trezor' with the 'o' omitted). Neither the whole-domain
typosquat candidate check nor the exact-substring combosquat check reaches a misspelling embedded inside an
unrelated, longer host.

The real design risk here (found while building this): a blanket edit-distance-1 check would also match
ordinary, harmless words that happen to differ from a brand name by one SUBSTITUTED letter ('cooking' from
'Booking', 'googles' from 'Google') - neither of those is a documented phishing shape. Reusing
generate_candidates' own narrow perturbation set (omission, transposition, repetition, digit-homoglyph -
never arbitrary substitution) closes that hole for free, confirmed below."""
from usi.heuristics import typosquat
from usi.models import Severity

BRANDS = typosquat.load_brands()


def signal(host):
    return typosquat.find_fuzzy_brand_token_match(host, BRANDS)


def via_run_all(host):
    sigs = typosquat.run_all(host, BRANDS)
    return sigs[0] if sigs else None


# --- must fire ---

def test_reported_trezor_misspelling_is_caught():
    s = signal("not-start-eng-trezr.pages.dev")
    assert s is not None and s.code == "fuzzy_brand_token_match"
    assert s.severity == Severity.HIGH
    assert s.evidence["brand"] == "Trezor"
    assert s.evidence["misspelled_as"] == "trezr"


def test_reaches_run_all():
    s = via_run_all("not-start-eng-trezr.pages.dev")
    assert s is not None and s.code == "fuzzy_brand_token_match"


def test_a_repeated_letter_misspelling_is_caught():
    s = signal("netflixx.weebly.com")
    assert s is not None and s.evidence["brand"] == "Netflix"


def test_an_omitted_letter_misspelling_is_caught():
    s = signal("microsof.weebly.com")
    assert s is not None and s.evidence["brand"] == "Microsoft"


def test_a_digit_homoglyph_misspelling_is_caught():
    s = signal("tr3zor.weebly.com")
    assert s is not None and s.evidence["brand"] == "Trezor"


# --- must NOT fire ---

def test_substitution_based_coincidences_stay_clean():
    # The real design risk: a blanket edit-distance check WOULD match these (one substituted letter), but
    # neither is a documented phishing shape, and both are plausible ordinary free-hosting site names.
    assert signal("cooking.weebly.com") is None    # one letter from "Booking"
    assert signal("googles.weebly.com") is None    # one letter from "Google" (caught, correctly, by the
                                                     # separate exact-substring combosquat rule instead)


def test_the_brands_own_real_domain_is_clean():
    assert signal("trezor.io") is None
    assert signal("www.trezor.io") is None


def test_not_on_free_hosting_this_rule_does_not_apply():
    # trezr.io is still caught overall - by the pre-existing whole-domain typosquat check - just not by
    # this rule, which is scoped to free-hosting platforms only.
    assert signal("trezr.io") is None


def test_an_unrelated_host_is_clean():
    assert signal("mysite.weebly.com") is None


def test_the_misspelling_inside_a_compound_word_is_not_a_standalone_token():
    assert signal("mycooking-blog.weebly.com") is None


def test_short_brand_names_are_excluded():
    # DHL/UPS-style short names are far too easy to coincidentally misspell into or out of ordinary words.
    assert signal("dh1.weebly.com") is None
    assert signal("ap0ple.weebly.com") is None

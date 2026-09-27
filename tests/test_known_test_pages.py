"""Found after a real check on https://www.amtso.org/check-desktop-phishing-page came back "Likely Safe" with
nothing to say the page is a well-known, industry-published security-test artifact rather than an ordinary safe
page - a browser extension flagged the same URL "Risky / Phishing" purely from a vendor-added test signature."""
from usi.heuristics import known_test_pages


def test_the_real_amtso_phishing_test_page_is_recognised():
    sig = known_test_pages.check("amtso.org", "https://www.amtso.org/check-desktop-phishing-page")
    assert sig is not None
    assert sig.code == "amtso_test_page"
    assert sig.severity.name == "INFO"


def test_the_www_host_and_the_newer_url_convention_are_also_recognised():
    sig = known_test_pages.check("www.amtso.org", "https://www.amtso.org/feature-settings-check-phishing-page/")
    assert sig is not None


def test_other_amtso_feature_check_pages_are_recognised():
    for path in (
        "https://amtso.org/check-desktop-malware-download-page",
        "https://amtso.org/check-desktop-pua-page",
        "https://amtso.org/check-desktop-drive-by-download-page",
        "https://amtso.org/feature-settings-check-cloud-lookup-page/",
    ):
        assert known_test_pages.check("amtso.org", path) is not None, path


def test_an_ordinary_amtso_page_is_not_flagged():
    assert known_test_pages.check("www.amtso.org", "https://www.amtso.org/about-us/") is None


def test_a_different_domain_with_a_similar_looking_path_is_not_flagged():
    # The path shape alone must never be enough - only AMTSO's own real domain gets this signal, so a phishing
    # page hosted elsewhere cannot borrow the "known test page" note by copying AMTSO's URL convention.
    assert known_test_pages.check("example.com", "https://example.com/check-desktop-phishing-page") is None
    assert known_test_pages.check("amtso.org.evil-lookalike.top", "https://amtso.org.evil-lookalike.top/check-desktop-phishing-page") is None


def test_an_ordinary_safe_site_is_not_flagged():
    assert known_test_pages.check("paypal.com", "https://paypal.com/") is None

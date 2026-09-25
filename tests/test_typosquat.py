from usi.heuristics import typosquat

BRANDS = [{"name": "PayPal", "domains": ["paypal.com"]}]


def test_real_domain_not_flagged():
    assert typosquat.find_typosquat_match("paypal.com", BRANDS) is None


def test_character_omission_flagged():
    # "paypal.com" with one char dropped -> "paypl.com" is a generated candidate
    sig = typosquat.find_typosquat_match("paypl.com", BRANDS)
    assert sig is not None
    assert sig.code == "typosquat_match"
    assert sig.evidence["brand"] == "PayPal"


def test_homoglyph_substitution_flagged():
    # "paypal" -> "payp4l" (a -> 4) is a generated candidate
    sig = typosquat.find_typosquat_match("payp4l.com", BRANDS)
    assert sig is not None


def test_unrelated_domain_not_flagged():
    assert typosquat.find_typosquat_match("stackoverflow.com", BRANDS) is None


def test_combosquat_keyword_match():
    sig = typosquat.find_combosquat_keyword_match("paypal-account-support-team.net", BRANDS)
    assert sig is not None
    assert sig.code == "combosquat_keyword_match"


def test_combosquat_ignores_legitimate_subdomain():
    assert typosquat.find_combosquat_keyword_match("www.paypal.com", BRANDS) is None


def test_kyc_keyword_generates_typosquat_candidate():
    # "KYC expiry" verification is the dominant lure in India's UPI/
    # banking-fraud campaigns per 2026 research - confirm it's wired
    # into candidate generation for a real bank brand.
    bank_brands = [{"name": "ICICI Bank", "domains": ["icicibank.com"]}]
    candidates = typosquat.generate_candidates("icicibank.com")
    assert "icicibank-kyc.com" in candidates or "kyc-icicibank.com" in candidates
    sig = typosquat.find_typosquat_match("icicibank-kyc.com", bank_brands)
    assert sig is not None
    assert sig.evidence["brand"] == "ICICI Bank"


def test_generate_candidates_excludes_original():
    candidates = typosquat.generate_candidates("paypal.com")
    assert "paypal.com" not in candidates
    assert len(candidates) > 0


def test_brand_plus_phishing_keyword_is_high_not_medium():
    # Regression: "paypal-login.top"-style hosts earned a lone MEDIUM, which
    # never moves the verdict, so they were reported "Likely Safe".
    from usi.models import Severity
    sig = typosquat.find_combosquat_keyword_match("paypal-login.top", BRANDS)
    assert sig.severity == Severity.HIGH
    assert "login" in sig.evidence["keywords"]


def test_brand_without_keyword_stays_medium():
    from usi.models import Severity
    sig = typosquat.find_combosquat_keyword_match("paypal-fans.net", BRANDS)
    assert sig is not None and sig.severity == Severity.MEDIUM
    assert sig.evidence["keywords"] == []


def test_digit_homoglyph_combosquat_is_caught():
    # Regression: "paypa1-login.top" (1 for l) sailed past the raw substring
    # check for "paypal" and was reported "Likely Safe".
    from usi.models import Severity
    for host in ("paypa1-login.top", "secure-paypa1.com", "p4ypal-verify.net"):
        sig = typosquat.find_combosquat_keyword_match(host, BRANDS)
        assert sig is not None, host
        assert sig.severity == Severity.HIGH, host


def test_rn_for_m_lookalike_is_caught():
    brands = [{"name": "Microsoft", "domains": ["microsoft.com"]}]
    assert typosquat.find_combosquat_keyword_match("rnicrosoft-support.com", brands) is not None


def test_keyword_must_be_its_own_label_not_a_substring():
    from usi.models import Severity
    # "idea" contains "id", "helpful" contains "help" - neither is a keyword label.
    for host in ("paypal-idea.net", "paypal-helpful.net"):
        assert typosquat.find_combosquat_keyword_match(host, BRANDS).severity == Severity.MEDIUM


def test_legitimate_brand_subdomain_and_domain_still_never_flagged():
    for host in ("login.paypal.com", "paypal.com", "www.paypal.com"):
        assert typosquat.find_combosquat_keyword_match(host, BRANDS) is None


def test_another_brands_real_domain_is_never_a_lookalike():
    # Regression: metamask.io (the real MetaMask site) was flagged as a
    # combosquat of the shorter brand "Meta", because only the *current*
    # brand's own domains were exempted.
    brands = [
        {"name": "Meta", "domains": ["facebook.com", "meta.com"]},
        {"name": "MetaMask", "domains": ["metamask.io"]},
    ]
    for host in ("metamask.io", "support.metamask.io", "facebook.com", "meta.com"):
        assert typosquat.find_combosquat_keyword_match(host, brands) is None, host
        assert typosquat.find_typosquat_match(host, brands) is None, host
    assert typosquat.find_combosquat_keyword_match("metamask-verify.top", brands).evidence["brand"] == "MetaMask"


def test_short_brand_names_need_own_label_plus_keyword():
    from usi.models import Severity
    brands = [{"name": "DHL", "domains": ["dhl.com"]}, {"name": "UPS", "domains": ["ups.com"]}]
    for host in ("dhl-parcel-verify.top", "ups-support.net", "secure-dhl.online"):
        sig = typosquat.find_combosquat_keyword_match(host, brands)
        assert sig is not None and sig.severity == Severity.HIGH, host
    # Not a whole label, or no keyword -> stays quiet (short names are too
    # likely to be a substring of an ordinary word).
    for host in ("groups-and-cups.com", "dhl-fans.net", "ups-and-downs.com", "bedhl.com", "tracking.dhl.com"):
        assert typosquat.find_combosquat_keyword_match(host, brands) is None, host


def test_unrelated_domain_with_digits_not_flagged():
    assert typosquat.find_combosquat_keyword_match("shop4u-deals.com", BRANDS) is None


def test_combosquat_prefers_more_specific_brand_match():
    # Regression: a real phishing URL (metamask-connect.vercel.app) was
    # misattributed to "Meta" (Facebook's parent) instead of "MetaMask",
    # because "Meta" is a substring of "MetaMask" and sat earlier in the
    # brand list. The longer, more specific match must win regardless of
    # list order.
    brands = [
        {"name": "Meta", "domains": ["facebook.com", "meta.com"]},
        {"name": "MetaMask", "domains": ["metamask.io"]},
    ]
    sig = typosquat.find_combosquat_keyword_match("metamask-connect.vercel.app", brands)
    assert sig is not None
    assert sig.evidence["brand"] == "MetaMask"


def test_combosquat_prefers_specific_match_regardless_of_list_order():
    # Same scenario with the brand list order reversed - result must be
    # identical, proving the fix isn't just order-dependent luck.
    brands = [
        {"name": "MetaMask", "domains": ["metamask.io"]},
        {"name": "Meta", "domains": ["facebook.com", "meta.com"]},
    ]
    sig = typosquat.find_combosquat_keyword_match("metamask-connect.vercel.app", brands)
    assert sig is not None
    assert sig.evidence["brand"] == "MetaMask"


# --- 2026-09-25: name the real website; SingPost lookalike (xzy-singpost.com, a live scam) ---

def test_combosquat_message_and_evidence_name_the_real_website():
    brands = [{"name": "SingPost", "domains": ["singpost.com"]}]
    sig = typosquat.find_combosquat_keyword_match("xzy-singpost.com", brands)
    assert sig is not None
    assert "The real SingPost website is singpost.com." in sig.message
    assert sig.evidence["real_domains"] == ["singpost.com"]
    assert sig.evidence["brand_is_whole_label"] is True


def test_typosquat_message_names_the_real_website():
    sig = typosquat.find_typosquat_match("paypl.com", BRANDS)
    assert "The real PayPal website is paypal.com." in sig.message
    assert sig.evidence["real_domains"] == ["paypal.com"]


def test_brand_name_only_as_a_substring_is_not_a_whole_label():
    brands = [{"name": "Meta", "domains": ["meta.com"]}]
    sig = typosquat.find_combosquat_keyword_match("metallica-fans.com", brands)
    assert sig is not None and sig.evidence["brand_is_whole_label"] is False


def test_shipped_brand_list_knows_singpost_and_the_real_site():
    brands = typosquat.load_brands()
    sigs = typosquat.run_all("xzy-singpost.com", brands)
    assert sigs and "singpost.com" in sigs[0].message
    assert typosquat.run_all("singpost.com", brands) == []
    assert typosquat.run_all("www.singpost.com", brands) == []
    assert typosquat.run_all("singpass.gov.sg", brands) == []

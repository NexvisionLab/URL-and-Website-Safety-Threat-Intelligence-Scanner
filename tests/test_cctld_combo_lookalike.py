"""ccTLD-combo lookalike (2026-10-20): a host shaped '<brand>.com.<cc>' impersonating a brand's plain
'<brand>.com' domain by appending a country-code suffix that reads, at a glance, like a genuine regional
site - the way amazon.com.au or amazon.co.jp really are. Documented miss from the 2026-09-27 OpenPhish
sample: roblox.com.am (Roblox has no ccTLD domain at all)."""
from usi.heuristics import typosquat
from usi.models import Severity

BRANDS = typosquat.load_brands()


def signal(host):
    return typosquat.find_cctld_combo_lookalike(host, BRANDS)


def via_run_all(host):
    sigs = typosquat.run_all(host, BRANDS)
    return sigs[0] if sigs else None


# --- must fire ---

def test_reported_roblox_lookalike_is_caught():
    s = signal("roblox.com.am")
    assert s is not None and s.code == "cctld_combo_lookalike"
    assert s.severity == Severity.HIGH
    assert s.evidence["brand"] == "Roblox"
    assert "roblox.com" in s.message


def test_another_six_letter_brand_with_no_cctld_domain_is_caught():
    s = signal("trezor.com.am")
    assert s is not None and s.code == "cctld_combo_lookalike"


def test_reaches_run_all():
    s = via_run_all("roblox.com.am")
    assert s is not None and s.code == "cctld_combo_lookalike"


# --- must NOT fire (this rule specifically - other rules may still catch a weaker signal) ---

def test_brands_with_a_genuine_cctld_combo_domain_stay_clean():
    # These brands DO have a real com.<cc> domain somewhere in brands.json, so appending a different one
    # is still worth the existing (weaker) combosquat check, not this HIGH rule.
    for host in ["amazon.com.au", "paypal.com.br", "shopee.com.my", "google.com.au", "zoom.com.cn"]:
        assert signal(host) is None, host


def test_short_ordinary_word_brand_names_do_not_trip_it_alone():
    for host in ["apple.com.de", "zoom.com.de", "steam.com.de"]:
        assert signal(host) is None, host


def test_a_non_exact_name_does_not_trip_it():
    for host in ["notroblox.com.am", "robloxx.com.am", "roblox-support.com.am"]:
        assert signal(host) is None, host


def test_suffixes_outside_the_known_combo_list_are_not_checked_by_this_rule():
    # amazon.com.cn is not in brands.json, and "cn" is not in the combo list this rule watches - left to
    # other checks (plain TLD-swap/combosquat), not duplicated here.
    assert signal("amazon.com.cn") is None


def test_the_real_plain_domain_is_clean():
    assert signal("roblox.com") is None


def test_a_real_subdomain_of_the_brands_own_domain_is_clean():
    assert signal("www.roblox.com") is None

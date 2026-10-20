"""Brand-domain-label lookalike (2026-10-20): a host that imitates a brand's multi-label service
domain by near-matching its labels, even across a different public suffix. Reported case:
team.lives.cn.com imitating teams.live.com, which the name/alias combosquat check and the
single-edit candidate generator both missed."""
from usi.heuristics import typosquat
from usi.models import Severity

BRANDS = typosquat.load_brands()


def signal(host):
    sigs = typosquat.run_all(host, BRANDS)
    return sigs[0] if sigs else None


# --- must fire ---

def test_reported_teams_live_lookalike_is_caught():
    s = signal("team.lives.cn.com")
    assert s is not None and s.code == "brand_domain_lookalike"
    assert s.severity == Severity.HIGH
    assert s.evidence["brand"] == "Microsoft"
    assert s.evidence["resembles_domain"] == "teams.live.com"
    assert "teams.live.com" in s.message


def test_subdomain_prefix_deception_is_caught():
    # the real brand domain planted as a subdomain of an attacker-owned domain
    s = signal("teams.live.com.account-verify.net")
    assert s is not None and s.code == "brand_domain_lookalike"


def test_near_match_of_meet_google_is_caught():
    s = signal("meat.googie.com")
    assert s is not None and s.code == "brand_domain_lookalike"
    assert s.evidence["resembles_domain"] == "meet.google.com"


def test_label_edit_plus_suffix_swap_is_caught():
    # 'team' (not teams) + '.co' (not .com) is two edits from teams.live.com, so the single-edit
    # candidate generator misses it; only the label-lookalike rule catches it.
    s = signal("team.live.co")
    assert s is not None and s.code == "brand_domain_lookalike"


# --- must NOT fire ---

def test_real_service_domains_are_clean():
    for host in ["teams.live.com", "teams.microsoft.com", "meet.google.com",
                 "login.live.com", "docs.google.com", "outlook.live.com"]:
        assert signal(host) is None, host


def test_cctld_brand_domains_are_not_treated_as_service_subdomains():
    for host in ["amazon.com.au", "paypal.co.uk", "google.co.in", "shopee.co.id"]:
        assert signal(host) is None, host


def test_ordinary_hosts_with_one_brandish_word_do_not_trip():
    for host in ["team.livestream.com", "my.team.com", "liveteam.com",
                 "livescore.com", "teamviewer.com", "livenation.com"]:
        assert signal(host) is None, host

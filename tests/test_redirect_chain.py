from usi.heuristics import redirect_chain
from usi.models import RedirectHop


def test_no_chain_returns_empty():
    assert redirect_chain.analyze("example.com", "example.com", []) == []


def test_single_hop_same_domain_is_info_only():
    chain = [RedirectHop(url="http://example.com/", host="example.com", status=301)]
    signals = redirect_chain.analyze("example.com", "www.example.com", chain)
    assert len(signals) == 1
    assert signals[0].code == "redirect_chain_summary"
    from usi.models import Severity
    assert signals[0].severity == Severity.INFO


def test_landed_on_different_domain_flagged():
    chain = [RedirectHop(url="http://short.link/x", host="short.link", status=301)]
    signals = redirect_chain.analyze("short.link", "evil-phish.top", chain)
    codes = {s.code for s in signals}
    assert "landed_on_different_domain" in codes


def test_excessive_hops_flagged():
    chain = [RedirectHop(url=f"http://hop{i}.com/", host=f"hop{i}.com", status=301) for i in range(6)]
    signals = redirect_chain.analyze("start.com", "hop5.com", chain)
    codes = {s.code for s in signals}
    assert "excessive_redirect_hops" in codes


def test_normal_hop_count_not_flagged_as_excessive():
    chain = [RedirectHop(url="http://a.com/", host="a.com", status=301)]
    signals = redirect_chain.analyze("a.com", "a.com", chain)
    codes = {s.code for s in signals}
    assert "excessive_redirect_hops" not in codes


def test_shortener_hop_flagged():
    chain = [RedirectHop(url="http://bit.ly/x", host="bit.ly", status=301)]
    signals = redirect_chain.analyze("bit.ly", "example.com", chain)
    codes = {s.code for s in signals}
    assert "redirect_through_shortener" in codes


def test_suspicious_tld_hop_flagged():
    chain = [RedirectHop(url="http://tracker.top/x", host="tracker.top", status=301)]
    signals = redirect_chain.analyze("tracker.top", "example.com", chain)
    codes = {s.code for s in signals}
    assert "redirect_through_suspicious_tld" in codes

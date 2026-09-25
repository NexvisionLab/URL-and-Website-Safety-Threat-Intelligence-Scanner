from usi.heuristics import url_structure


def test_ip_literal_host_flagged():
    sig = url_structure.check_ip_literal_host("192.168.1.1")
    assert sig is not None
    assert sig.code == "ip_literal_host"


def test_normal_host_not_flagged():
    assert url_structure.check_ip_literal_host("example.com") is None


def test_at_symbol_flagged():
    sig = url_structure.check_at_symbol("http://real-bank.com@evil.tld/login")
    assert sig is not None
    assert sig.code == "at_symbol_in_authority"


def test_no_at_symbol_not_flagged():
    assert url_structure.check_at_symbol("http://example.com/path") is None


def test_excessive_subdomains_flagged():
    sig = url_structure.check_subdomain_count("a.b.c.d.example.com")
    assert sig is not None
    assert sig.code == "excessive_subdomains"


def test_reasonable_subdomains_not_flagged():
    assert url_structure.check_subdomain_count("www.example.com") is None


def test_excessive_hyphens_flagged():
    sig = url_structure.check_hyphen_count("secure-login-account-verify-now-please.com")
    assert sig is not None
    assert sig.code == "excessive_hyphens"


def test_reasonable_hyphens_not_flagged():
    assert url_structure.check_hyphen_count("my-example-site.com") is None


def test_suspicious_tld_flagged():
    sig = url_structure.check_suspicious_tld("free-prize.top")
    assert sig is not None
    assert sig.code == "suspicious_tld"


def test_legit_tld_not_flagged():
    assert url_structure.check_suspicious_tld("example.com") is None


def test_known_shortener_flagged():
    sig = url_structure.check_known_shortener("bit.ly")
    assert sig is not None
    assert sig.code == "url_shortener"


def test_run_all_returns_list():
    signals = url_structure.run_all("http://192.168.1.1@evil.top/free-prize-now-secure-login", "192.168.1.1")
    codes = {s.code for s in signals}
    assert "ip_literal_host" in codes
    assert "at_symbol_in_authority" in codes

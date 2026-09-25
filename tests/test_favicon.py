from usi.content import favicon


def test_find_declared_favicon_url_from_link_tag():
    html = '<html><head><link rel="icon" href="/assets/icon.ico"></head></html>'
    url = favicon.find_declared_favicon_url(html, "https://example.com/page")
    assert url == "https://example.com/assets/icon.ico"


def test_find_declared_favicon_url_falls_back_to_default():
    url = favicon.find_declared_favicon_url("<html></html>", "https://example.com/page")
    assert url == "https://example.com/favicon.ico"


def test_find_declared_favicon_url_handles_no_html():
    url = favicon.find_declared_favicon_url(None, "https://example.com/page")
    assert url == "https://example.com/favicon.ico"


def test_real_brand_domain_never_flagged(monkeypatch):
    # Simulate a matching hash but on the brand's OWN domain - must not flag.
    import requests

    class FakeResp:
        status_code = 200
        class raw:
            @staticmethod
            def read(n, decode_content=True):
                return b"x" * 100

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    monkeypatch.setattr(
        "usi.content.favicon.hashlib.md5",
        lambda content: type("H", (), {"hexdigest": lambda self: "deadbeef"})(),
    )

    brands = [{"name": "TestBrand", "domains": ["testbrand.com"]}]
    known_hashes = {"TestBrand": {"domain": "testbrand.com", "md5": "deadbeef"}}

    sig = favicon.check(
        host="testbrand.com", favicon_url="https://testbrand.com/favicon.ico",
        user_agent="test", brands=brands, known_hashes=known_hashes,
    )
    assert sig is None


def test_matching_hash_on_lookalike_domain_flagged(monkeypatch):
    import requests

    class FakeResp:
        status_code = 200
        class raw:
            @staticmethod
            def read(n, decode_content=True):
                return b"x" * 100

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    monkeypatch.setattr(
        "usi.content.favicon.hashlib.md5",
        lambda content: type("H", (), {"hexdigest": lambda self: "deadbeef"})(),
    )

    brands = [{"name": "TestBrand", "domains": ["testbrand.com"]}]
    known_hashes = {"TestBrand": {"domain": "testbrand.com", "md5": "deadbeef"}}

    sig = favicon.check(
        host="testbrand-login.top", favicon_url="https://testbrand-login.top/favicon.ico",
        user_agent="test", brands=brands, known_hashes=known_hashes,
    )
    assert sig is not None
    assert sig.code == "favicon_matches_brand"


def test_no_known_hashes_returns_none():
    sig = favicon.check(
        host="example.com", favicon_url="https://example.com/favicon.ico",
        user_agent="test", brands=[], known_hashes={},
    )
    assert sig is None

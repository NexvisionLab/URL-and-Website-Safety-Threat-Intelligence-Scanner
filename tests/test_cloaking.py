from usi.content import cloaking
from usi.models import Severity


class FakeResp:
    def __init__(self, status_code, content):
        self.status_code = status_code
        self._capped_content = content


def test_consistent_response_is_info_only(monkeypatch):
    monkeypatch.setattr(
        cloaking, "capped_get", lambda session, url, timeout, max_bytes: FakeResp(200, b"x" * 1000)
    )
    sig = cloaking.check(
        url="https://example.com", primary_status=200, primary_size=1000,
        timeout=10, max_bytes=2_000_000,
    )
    assert sig is not None
    assert sig.code == "cloaking_check_consistent"
    assert sig.severity == Severity.INFO


def test_status_mismatch_flagged(monkeypatch):
    monkeypatch.setattr(
        cloaking, "capped_get", lambda session, url, timeout, max_bytes: FakeResp(200, b"x" * 1000)
    )
    sig = cloaking.check(
        url="https://example.com", primary_status=403, primary_size=1000,
        timeout=10, max_bytes=2_000_000,
    )
    assert sig is not None
    assert sig.code == "cloaking_status_mismatch"
    assert sig.severity == Severity.HIGH


def test_content_size_mismatch_flagged(monkeypatch):
    # Tool's own UA got a near-empty response, browser UA got real content.
    monkeypatch.setattr(
        cloaking, "capped_get", lambda session, url, timeout, max_bytes: FakeResp(200, b"x" * 5000)
    )
    sig = cloaking.check(
        url="https://example.com", primary_status=200, primary_size=50,
        timeout=10, max_bytes=2_000_000,
    )
    assert sig is not None
    assert sig.code == "cloaking_content_size_mismatch"
    assert sig.severity == Severity.HIGH


def test_similar_sizes_not_flagged(monkeypatch):
    monkeypatch.setattr(
        cloaking, "capped_get", lambda session, url, timeout, max_bytes: FakeResp(200, b"x" * 1050)
    )
    sig = cloaking.check(
        url="https://example.com", primary_status=200, primary_size=1000,
        timeout=10, max_bytes=2_000_000,
    )
    assert sig is not None
    assert sig.code == "cloaking_check_consistent"


def test_comparison_fetch_failure_returns_none(monkeypatch):
    def raise_error(*args, **kwargs):
        raise ConnectionError("boom")
    monkeypatch.setattr(cloaking, "capped_get", raise_error)
    sig = cloaking.check(
        url="https://example.com", primary_status=200, primary_size=1000,
        timeout=10, max_bytes=2_000_000,
    )
    assert sig is None


# --- 2026-09-25: a size gap alone is not cloaking (google.com false positive) ---

PAGE = "<html><head><title>Google</title></head><body><form action='/search'><input name='q'></form>{}</body></html>"


def _browser_returns(monkeypatch, html):
    monkeypatch.setattr(
        cloaking, "capped_get", lambda session, url, timeout, max_bytes: FakeResp(200, html.encode())
    )


def test_a_big_size_gap_with_the_same_page_is_not_cloaking(monkeypatch):
    # google.com: 88,237 bytes to the tool's User-Agent, 285,628 to Chrome, same title and search form
    tool_html, browser_html = PAGE.format("a" * 88000), PAGE.format("a" * 285000)
    _browser_returns(monkeypatch, browser_html)
    sig = cloaking.check(
        url="https://google.com", primary_status=200, primary_size=len(tool_html),
        timeout=10, max_bytes=2_000_000, primary_html=tool_html,
    )
    assert sig is not None
    assert sig.code == "cloaking_size_differs_content_same"
    assert sig.severity == Severity.INFO


def test_a_size_gap_with_a_different_title_is_still_flagged(monkeypatch):
    tool_html = "<html><head><title>Under construction</title></head><body>" + "a" * 1000 + "</body></html>"
    browser_html = "<html><head><title>Sign in to your bank</title></head><body>" + "a" * 5000 + "</body></html>"
    _browser_returns(monkeypatch, browser_html)
    sig = cloaking.check(
        url="https://example.com", primary_status=200, primary_size=len(tool_html),
        timeout=10, max_bytes=2_000_000, primary_html=tool_html,
    )
    assert sig.code == "cloaking_content_size_mismatch"
    assert sig.severity == Severity.HIGH
    assert sig.evidence["content_differs_in"] == ["title"]


def test_a_login_form_only_the_browser_sees_is_flagged(monkeypatch):
    tool_html = "<html><head><title>Welcome</title></head><body>" + "a" * 1000 + "</body></html>"
    browser_html = "<html><head><title>Welcome</title></head><body><form><input type='password'></form>" + "a" * 5000 + "</body></html>"
    _browser_returns(monkeypatch, browser_html)
    sig = cloaking.check(
        url="https://example.com", primary_status=200, primary_size=len(tool_html),
        timeout=10, max_bytes=2_000_000, primary_html=tool_html,
    )
    assert sig.code == "cloaking_content_size_mismatch"
    assert set(sig.evidence["content_differs_in"]) == {"password_field", "form"}


def test_a_near_empty_page_for_the_tool_is_flagged_even_if_the_html_is_supplied(monkeypatch):
    _browser_returns(monkeypatch, PAGE.format("a" * 5000))
    sig = cloaking.check(
        url="https://example.com", primary_status=200, primary_size=50,
        timeout=10, max_bytes=2_000_000, primary_html="<html></html>",
    )
    assert sig.code == "cloaking_content_size_mismatch"
    assert sig.severity == Severity.HIGH


def test_a_size_gap_without_the_tools_html_is_only_a_weak_hint(monkeypatch):
    _browser_returns(monkeypatch, PAGE.format("a" * 5000))
    sig = cloaking.check(
        url="https://example.com", primary_status=200, primary_size=1000, timeout=10, max_bytes=2_000_000,
    )
    assert sig.code == "cloaking_content_size_mismatch"
    assert sig.severity == Severity.MEDIUM

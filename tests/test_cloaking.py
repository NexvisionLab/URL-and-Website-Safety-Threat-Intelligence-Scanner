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

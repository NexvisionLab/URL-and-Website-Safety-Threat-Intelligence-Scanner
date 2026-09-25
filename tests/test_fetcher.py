import requests

from usi.content import fetcher
from usi.net import MAX_REDIRECTS, build_session


class FakeResp:
    def __init__(self, body=b"<html><title>Hi</title></html>", headers=None, status=200,
                 url="https://example.com/", history=None, encoding="utf-8"):
        self._capped_content = body
        self.headers = headers or {}
        self.status_code = status
        self.url = url
        self.history = history or []
        self.encoding = encoding


def _fetch(monkeypatch, resp):
    monkeypatch.setattr(fetcher, "capped_get", lambda *a, **k: resp)
    return fetcher.fetch("https://example.com/", timeout=5, max_bytes=1000, user_agent="t")


def test_html_response_is_decoded(monkeypatch):
    result = _fetch(monkeypatch, FakeResp(headers={"content-type": "text/html; charset=utf-8"}))
    assert result.reachable
    assert "<title>Hi</title>" in result.text
    assert result.content_type.startswith("text/html")


def test_missing_content_type_is_treated_as_text(monkeypatch):
    result = _fetch(monkeypatch, FakeResp(headers={}))
    assert result.text is not None


def test_binary_content_type_is_not_decoded(monkeypatch):
    resp = FakeResp(body=b"MZ\x90\x00binary", headers={"content-type": "application/x-msdownload"},
                    url="https://evil.top/Zoom.exe")
    result = _fetch(monkeypatch, resp)
    assert result.reachable
    assert result.text is None
    assert result.content_type == "application/x-msdownload"


def test_attachment_disposition_is_not_decoded_even_if_text(monkeypatch):
    resp = FakeResp(headers={"content-type": "text/plain",
                             "content-disposition": "attachment; filename=x.ps1"})
    result = _fetch(monkeypatch, resp)
    assert result.text is None
    assert "attachment" in result.content_disposition


def test_json_content_type_is_decoded(monkeypatch):
    result = _fetch(monkeypatch, FakeResp(body=b'{"a": 1}', headers={"content-type": "application/json"}))
    assert result.text == '{"a": 1}'


def test_redirect_history_is_captured(monkeypatch):
    hop = FakeResp(status=301, url="http://short.link/x")
    result = _fetch(monkeypatch, FakeResp(history=[hop], headers={"content-type": "text/html"}))
    assert len(result.redirect_chain) == 1
    assert result.redirect_chain[0].host == "short.link"
    assert result.redirect_chain[0].status == 301


def test_request_exception_becomes_unreachable(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("dns failure")
    monkeypatch.setattr(fetcher, "capped_get", boom)
    result = fetcher.fetch("https://nope.invalid/", timeout=5, max_bytes=1000, user_agent="t")
    assert result.reachable is False
    assert "dns failure" in result.error


def test_unexpected_exception_becomes_unreachable(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("weird")
    monkeypatch.setattr(fetcher, "capped_get", boom)
    result = fetcher.fetch("https://x.com/", timeout=5, max_bytes=1000, user_agent="t")
    assert result.reachable is False


def test_undecodable_encoding_name_is_reported_not_raised(monkeypatch):
    result = _fetch(monkeypatch, FakeResp(headers={"content-type": "text/html"}, encoding="no-such-codec"))
    assert result.reachable
    assert result.text is None
    assert "could not decode" in result.error


class _Raw:
    def __init__(self, chunks, clock=None, tick=0.0):
        self.chunks, self.clock, self.tick, self.reads = list(chunks), clock, tick, 0

    def read(self, n, decode_content=True):
        self.reads += 1
        if self.clock is not None:
            self.clock[0] += self.tick
        if not self.chunks:
            return b""
        head = self.chunks.pop(0)
        if len(head) > n:
            self.chunks.insert(0, head[n:])
            head = head[:n]
        return head


class _StreamResp:
    def __init__(self, raw):
        self.raw, self.closed = raw, False

    def close(self):
        self.closed = True


class _Session:
    def __init__(self, resp):
        self.resp = resp

    def get(self, *a, **k):
        return self.resp


def test_capped_get_reads_to_eof_joins_chunks_and_closes():
    from usi.net import capped_get
    resp = _StreamResp(_Raw([b"abc", b"def", b"ghi"]))
    out = capped_get(_Session(resp), "http://x", timeout=5, max_bytes=1000)
    assert out._capped_content == b"abcdefghi"
    assert resp.closed


def test_capped_get_stops_at_max_bytes_exactly():
    from usi.net import capped_get
    resp = _StreamResp(_Raw([b"x" * 500, b"y" * 500]))
    out = capped_get(_Session(resp), "http://x", timeout=5, max_bytes=600)
    assert len(out._capped_content) == 600
    assert resp.closed


def test_capped_get_total_timeout_stops_a_slow_drip_server(monkeypatch):
    # Regression: requests' timeout is per-socket-read, so a server sending
    # one byte at a time could hold the fetch open forever.
    from usi import net
    clock = [0.0]
    monkeypatch.setattr(net.time, "monotonic", lambda: clock[0])
    raw = _Raw([b"x"] * 10_000, clock=clock, tick=1.0)  # 1 "second" per byte
    resp = _StreamResp(raw)
    out = net.capped_get(_Session(resp), "http://x", timeout=5, max_bytes=10_000, total_timeout=20)
    assert 15 <= len(out._capped_content) <= 21
    assert raw.reads < 100
    assert resp.closed


def test_build_session_applies_redirect_cap_and_ua():
    s = build_session("my-agent/1.0")
    assert s.max_redirects == MAX_REDIRECTS == 5
    assert s.headers["User-Agent"] == "my-agent/1.0"


def test_build_session_routes_through_tor_proxy_when_given():
    s = build_session("ua", tor_proxy="socks5h://127.0.0.1:9050")
    assert s.proxies["https"] == "socks5h://127.0.0.1:9050"

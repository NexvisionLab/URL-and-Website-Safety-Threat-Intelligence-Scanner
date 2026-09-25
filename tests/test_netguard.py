"""The private-address guard must stop the tool reaching internal hosts, including via
redirects and page-declared favicons, and must stay out of the way when it is off."""
import http.server
import socket
import threading

import pytest
import requests

from usi import netguard
from usi.content import favicon, fetcher
from usi.lookups import tls_cert
from usi.net import build_session

PRIVATE_TARGETS = [
    "127.0.0.1", "localhost", "10.1.2.3", "192.168.0.10", "172.16.5.5",
    "169.254.169.254", "0.0.0.0", "[::1]", "::ffff:127.0.0.1", "100.64.0.1",
]


@pytest.fixture
def guard_on(monkeypatch):
    monkeypatch.setenv(netguard.ENV_VAR, "1")


@pytest.mark.parametrize("host", PRIVATE_TARGETS)
def test_private_and_loopback_targets_are_blocked(guard_on, host):
    with pytest.raises(netguard.BlockedAddressError):
        netguard.check_host(host)


@pytest.mark.parametrize("host", ["2130706433", "0x7f.0.0.1", "0177.0.0.1"])
def test_numeric_shorthand_for_loopback_is_blocked_wherever_the_system_resolves_it(guard_on, host):
    # Linux resolves these to 127.0.0.1 and would connect; Windows does not resolve them at all.
    # Either way the tool must never let an address through that the system would reach.
    try:
        resolves = bool(socket.getaddrinfo(host, None, type=socket.SOCK_STREAM))
    except (socket.gaierror, UnicodeError):
        resolves = False
    if resolves:
        with pytest.raises(netguard.BlockedAddressError):
            netguard.check_host(host)
    else:
        netguard.check_host(host)


def test_public_address_is_allowed(guard_on):
    netguard.check_host("93.184.216.34")


def test_name_resolving_to_private_address_is_blocked(guard_on, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 0))])
    with pytest.raises(netguard.BlockedAddressError):
        netguard.check_host("innocent.example")


def test_mixed_answer_with_one_private_address_is_blocked(guard_on, monkeypatch):
    answers = [(2, 1, 6, "", ("93.184.216.34", 0)), (2, 1, 6, "", ("127.0.0.1", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: answers)
    with pytest.raises(netguard.BlockedAddressError):
        netguard.check_host("rebinder.example")


def test_unresolvable_name_is_left_to_fail_on_its_own(guard_on, monkeypatch):
    def boom(*a, **k):
        raise socket.gaierror("no such host")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    netguard.check_host("does-not-exist.example")


def test_guard_is_inert_when_the_switch_is_off(monkeypatch):
    monkeypatch.delenv(netguard.ENV_VAR, raising=False)
    netguard.check_host("127.0.0.1")


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect-inward":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:%d/secret" % self.server.server_address[1])
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><title>internal</title>secret</html>")

    def log_message(self, *args):
        pass


@pytest.fixture
def local_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def test_fetcher_refuses_a_loopback_target(guard_on, local_server):
    result = fetcher.fetch(f"http://127.0.0.1:{local_server}/", timeout=3, max_bytes=10_000, user_agent="t")
    assert result.reachable is False
    assert "non-public" in (result.error or "")
    assert result.text is None


def test_fetcher_can_still_reach_loopback_when_guard_is_off(monkeypatch, local_server):
    monkeypatch.delenv(netguard.ENV_VAR, raising=False)
    result = fetcher.fetch(f"http://127.0.0.1:{local_server}/", timeout=3, max_bytes=10_000, user_agent="t")
    assert result.reachable is True and "secret" in result.text


def test_redirect_to_an_internal_address_is_blocked_mid_chain(guard_on, monkeypatch):
    # First hop resolves to a public address and answers 302 -> http://127.0.0.1/secret.
    # No socket is opened: the transport is replaced, but the guard still runs before it.
    import io
    from requests.adapters import HTTPAdapter

    real = socket.getaddrinfo
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))] if host == "first-hop.example" else real(host, *a, **k),
    )
    sent = []

    def fake_send(self, request, **kwargs):
        sent.append(request.url)
        response = requests.Response()
        response.request, response.url, response.raw = request, request.url, io.BytesIO(b"")
        if "first-hop.example" in request.url:
            response.status_code = 302
            response.headers["Location"] = "http://127.0.0.1/secret"
        else:
            response.status_code = 200
        return response

    monkeypatch.setattr(HTTPAdapter, "send", fake_send)
    with pytest.raises(netguard.BlockedAddressError):
        build_session("t").get("http://first-hop.example/start", timeout=3)
    assert sent == ["http://first-hop.example/start"]


def test_tls_lookup_refuses_an_internal_host(guard_on):
    signals = tls_cert.inspect("127.0.0.1")
    assert signals[0].code == "tls_unavailable" and "non-public" in signals[0].message


def test_favicon_fetch_refuses_an_internal_address(guard_on, local_server):
    hashes = {"Brand": {"md5": "0" * 32, "domains": ["brand.example"]}}
    signal = favicon.check(
        "lookalike.example", f"http://127.0.0.1:{local_server}/favicon.ico", "t",
        [{"name": "Brand", "domains": ["brand.example"]}], known_hashes=hashes,
    )
    assert signal is None


def test_tor_requests_are_not_checked_locally(guard_on):
    session = build_session("t", tor_proxy="socks5h://127.0.0.1:9050")
    assert session.proxies["http"].startswith("socks5h")
    assert not isinstance(session.get_adapter("http://x.onion/"), netguard.GuardedAdapter)

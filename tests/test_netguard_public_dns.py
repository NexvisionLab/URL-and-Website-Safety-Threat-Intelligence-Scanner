"""A name the system resolver maps to a private address (a VPN's region-unblocking DNS answers for
bbc.com with 10.240.x.x) is checked against public resolvers instead, and connected to by the
address they give. Nothing here touches the network: the resolvers and the system resolver are stubbed.

    python -m pytest tests/test_netguard_public_dns.py -q
"""
import socket
import struct
import threading
import time

import pytest
import requests
from requests.adapters import HTTPAdapter

from usi import netguard

VPN_ANSWER = [(2, 1, 6, "", ("10.240.3.136", 0))]


@pytest.fixture(autouse=True)
def guard_on(monkeypatch):
    monkeypatch.setenv(netguard.ENV_VAR, "1")


@pytest.fixture
def system_says_private(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: VPN_ANSWER)


def resolvers(monkeypatch, answers):
    """answers: {resolver_ip: [addresses]}; a resolver not listed gives no answer."""
    calls = []

    def fake(resolver, name):
        calls.append((resolver, name))
        return list(answers.get(resolver, []))

    monkeypatch.setattr(netguard, "PUBLIC_RESOLVERS", tuple(answers) or ("1.1.1.1", "9.9.9.9"))
    monkeypatch.setattr(netguard, "_query_a", fake)
    return calls


def packet(query_id, addresses, rcode=0, flags_extra=0x8180, pointer_names=True):
    """A DNS response for bbc.com carrying the given A records."""
    question = b"\x03bbc\x03com\x00" + struct.pack(">HH", 1, 1)
    header = struct.pack(">HHHHHH", query_id, flags_extra | rcode, 1, len(addresses), 0, 0)
    body = b""
    for address in addresses:
        body += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
    return header + question + body


class TestPacketParsing:
    def test_a_records_are_read_through_name_compression(self):
        assert netguard._parse_a_records(packet(7, ["151.101.0.81", "151.101.64.81"]), 7) == ["151.101.0.81", "151.101.64.81"]

    def test_a_response_with_another_id_is_ignored(self):
        assert netguard._parse_a_records(packet(7, ["151.101.0.81"]), 8) == []

    def test_an_error_code_gives_nothing(self):
        assert netguard._parse_a_records(packet(7, [], rcode=3), 7) == []        # NXDOMAIN

    def test_a_query_rather_than_a_response_is_ignored(self):
        assert netguard._parse_a_records(packet(7, ["151.101.0.81"], flags_extra=0x0100), 7) == []

    def test_non_a_records_are_skipped(self):
        data = packet(7, ["151.101.0.81"])
        cname = b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, 2) + b"\xc0\x0c"
        head = struct.pack(">HHHHHH", 7, 0x8180, 1, 2, 0, 0)
        question = data[12:12 + len(b"\x03bbc\x03com\x00") + 4]
        assert netguard._parse_a_records(head + question + cname + data[12 + len(question):], 7) == ["151.101.0.81"]

    @pytest.mark.parametrize("cut", [0, 5, 11, 20, 30])
    def test_truncated_packets_raise_or_return_nothing_and_never_crash(self, cut):
        data = packet(7, ["151.101.0.81"])[:cut]
        try:
            assert netguard._parse_a_records(data, 7) == []
        except ValueError:
            pass

    def test_garbage_does_not_loop_or_crash(self):
        start = time.time()
        for blob in (b"\x00" * 400, b"\xff" * 400, bytes(range(256)) * 2):
            try:
                netguard._parse_a_records(blob, 0)
            except ValueError:
                pass
        assert time.time() - start < 1

    def test_the_query_is_a_well_formed_a_question(self):
        query = netguard._build_query("bbc.com", 0x1234)
        assert query[:2] == b"\x12\x34" and query[12:] == b"\x03bbc\x03com\x00\x00\x01\x00\x01"


class TestFallbackDecision:
    def test_a_name_the_vpn_maps_privately_is_allowed_via_the_address_public_dns_gives(self, system_says_private, monkeypatch):
        resolvers(monkeypatch, {"1.1.1.1": ["151.101.0.81"], "9.9.9.9": ["151.101.64.81"]})
        assert netguard.vet_host("bbc.com") == "151.101.0.81"
        netguard.check_host("bbc.com")                       # no exception

    def test_one_resolver_failing_is_fine_when_the_other_answers_publicly(self, system_says_private, monkeypatch):
        resolvers(monkeypatch, {"1.1.1.1": [], "9.9.9.9": ["151.101.64.81"]})
        assert netguard.vet_host("bbc.com") == "151.101.64.81"

    def test_no_answer_from_any_public_resolver_stays_blocked(self, system_says_private, monkeypatch):
        resolvers(monkeypatch, {"1.1.1.1": [], "9.9.9.9": []})
        with pytest.raises(netguard.BlockedAddressError):
            netguard.check_host("intranet.corp.example")

    def test_a_private_address_from_any_resolver_blocks_even_if_another_is_public(self, system_says_private, monkeypatch):
        resolvers(monkeypatch, {"1.1.1.1": ["151.101.0.81"], "9.9.9.9": ["10.0.0.5"]})
        with pytest.raises(netguard.BlockedAddressError):
            netguard.check_host("mixed.example")

    def test_a_public_resolver_returning_loopback_stays_blocked(self, system_says_private, monkeypatch):
        resolvers(monkeypatch, {"1.1.1.1": ["127.0.0.1"], "9.9.9.9": []})
        with pytest.raises(netguard.BlockedAddressError):
            netguard.check_host("rebind.example")

    @pytest.mark.parametrize("host", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "[::1]", "localhost",
                                       "2130706433", "0x7f.0.0.1", "0177.0.0.1", "intranet"])
    def test_literals_shorthand_and_single_labels_never_use_the_fallback(self, host, monkeypatch):
        calls = resolvers(monkeypatch, {"1.1.1.1": ["151.101.0.81"], "9.9.9.9": ["151.101.0.81"]})
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 0))])
        with pytest.raises(netguard.BlockedAddressError):
            netguard.check_host(host)
        assert calls == []

    def test_a_name_with_a_public_system_answer_never_asks_public_dns(self, monkeypatch):
        calls = resolvers(monkeypatch, {"1.1.1.1": ["1.2.3.4"]})
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
        assert netguard.vet_host("example.com") is None
        assert calls == []

    def test_the_guard_off_does_nothing(self, monkeypatch, system_says_private):
        monkeypatch.delenv(netguard.ENV_VAR)
        calls = resolvers(monkeypatch, {"1.1.1.1": ["151.101.0.81"]})
        assert netguard.vet_host("bbc.com") is None and calls == []

    @pytest.mark.parametrize("name", ["bbc.com", "a-b.example.co.uk", "x1.io"])
    def test_dns_names_are_recognised(self, name):
        assert netguard._looks_like_dns_name(name)

    @pytest.mark.parametrize("name", ["localhost", "10.0.0.1", "0x7f.0.0.1", "2130706433", "a..b", "-.com.", "bad_name.com", ("a" * 64) + ".com"])
    def test_other_forms_are_not(self, name):
        assert not netguard._looks_like_dns_name(name)


class TestPinnedConnection:
    def test_the_adapter_connects_to_the_public_address_and_cleans_up(self, system_says_private, monkeypatch):
        resolvers(monkeypatch, {"1.1.1.1": ["151.101.0.81"]})
        seen = []

        def fake_send(self, request, **kwargs):
            seen.append(dict(getattr(netguard._local, "pins", None) or {}))
            response = requests.Response()
            response.status_code, response.request, response.url = 200, request, request.url
            return response

        monkeypatch.setattr(HTTPAdapter, "send", fake_send)
        session = requests.Session()
        session.mount("https://", netguard.GuardedAdapter())
        assert session.get("https://BBC.com/news", timeout=3).status_code == 200
        assert seen == [{"bbc.com": "151.101.0.81"}]
        assert getattr(netguard._local, "pins", None) is None            # not left behind for the next request

    def test_pins_are_cleared_when_the_request_fails(self, system_says_private, monkeypatch):
        resolvers(monkeypatch, {"1.1.1.1": ["151.101.0.81"]})

        def boom(self, request, **kwargs):
            raise requests.ConnectionError("down")

        monkeypatch.setattr(HTTPAdapter, "send", boom)
        session = requests.Session()
        session.mount("https://", netguard.GuardedAdapter())
        with pytest.raises(requests.ConnectionError):
            session.get("https://bbc.com/", timeout=3)
        assert getattr(netguard._local, "pins", None) is None

    def test_the_connection_hook_substitutes_only_the_pinned_host(self, monkeypatch):
        recorded = []
        monkeypatch.setattr(netguard, "_original_create_connection", lambda address, *a, **k: recorded.append(address))
        netguard._local.pins = {"bbc.com": "151.101.0.81"}
        try:
            netguard._create_connection(("bbc.com", 443))
            netguard._create_connection(("other.example", 443))
        finally:
            netguard._local.pins = None
        netguard._create_connection(("bbc.com", 443))
        assert recorded == [("151.101.0.81", 443), ("other.example", 443), ("bbc.com", 443)]

    def test_pins_do_not_leak_between_threads(self, monkeypatch):
        recorded = []
        monkeypatch.setattr(netguard, "_original_create_connection", lambda address, *a, **k: recorded.append(address))
        netguard._local.pins = {"bbc.com": "151.101.0.81"}
        try:
            worker = threading.Thread(target=lambda: netguard._create_connection(("bbc.com", 443)))
            worker.start()
            worker.join()
        finally:
            netguard._local.pins = None
        assert recorded == [("bbc.com", 443)]

    def test_a_private_redirect_hop_is_still_blocked(self, monkeypatch):
        # public site -> 302 to a host whose names resolve privately and have no public answer
        resolvers(monkeypatch, {"1.1.1.1": [], "9.9.9.9": []})
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.9", 0))])
        session = requests.Session()
        session.mount("http://", netguard.GuardedAdapter())
        with pytest.raises(netguard.BlockedAddressError):
            session.get("http://internal.corp.example/", timeout=3)

    def test_create_connection_helper_connects_to_the_vetted_address(self, system_says_private, monkeypatch):
        resolvers(monkeypatch, {"1.1.1.1": ["151.101.0.81"]})
        recorded = []
        monkeypatch.setattr(socket, "create_connection", lambda address, timeout=None: recorded.append((address, timeout)) or "sock")
        assert netguard.create_connection("bbc.com", 443, 10) == "sock"
        assert recorded == [(("151.101.0.81", 443), 10)]

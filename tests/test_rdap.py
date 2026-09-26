"""RDAP parsing and server selection, all offline."""
from datetime import datetime, timezone

import pytest

from usi.lookups import rdap

# Trimmed from SGNIC's real answer for lazada.sg (2026-09-25).
SGNIC_SAMPLE = {
    "ldhName": "lazada.sg",
    "events": [
        {"eventAction": "registration", "eventDate": "2012-02-22T12:48:48Z"},
        {"eventAction": "expiration", "eventDate": "2028-02-22T12:48:48Z"},
        {"eventAction": "last changed", "eventDate": "2026-08-28T08:50:16Z"},
    ],
    "entities": [
        {"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "MarkMonitor Inc."]]]},
        {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "LAZADA SOUTH EAST ASIA PTE. LTD."]]]},
    ],
}


def test_parse_reads_dates_registrar_and_registrant():
    out = rdap.parse(SGNIC_SAMPLE)
    assert out["created"] == datetime(2012, 2, 22, 12, 48, 48, tzinfo=timezone.utc)
    assert out["expires"].year == 2028
    assert out["last_changed"].year == 2026
    assert out["registrar"] == "MarkMonitor Inc."
    assert out["registrant"] == "LAZADA SOUTH EAST ASIA PTE. LTD."


def test_redacted_registrant_is_dropped():
    data = {"events": [], "entities": [
        {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"]]]}]}
    assert rdap.parse(data)["registrant"] is None


def test_malformed_entities_do_not_crash():
    data = {"events": [{"eventAction": "registration", "eventDate": "not a date"}],
            "entities": [{"roles": ["registrar"], "vcardArray": "junk"}, {"roles": None}]}
    out = rdap.parse(data)
    assert out["created"] is None and out["registrar"] is None


@pytest.mark.parametrize("host,expected", [
    ("www.lazada.sg", "lazada.sg"),
    ("shop.example.com.sg", "example.com.sg"),
    ("Walkingmats.com.", "walkingmats.com"),
    ("localhost", None),
])
def test_registrable_domain(host, expected):
    assert rdap.registrable_domain(host) == expected


class _Resp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload


def test_registration_queries_the_tld_server(monkeypatch, tmp_path):
    monkeypatch.setattr(rdap, "_bootstrap_memo", {"sg": "https://rdap.sgnic.sg/rdap/"})
    seen = {}

    def fake_get(url, timeout, headers):
        seen["url"] = url
        return _Resp(200, SGNIC_SAMPLE)
    monkeypatch.setattr(rdap.requests, "get", fake_get)
    out = rdap.registration("www.lazada.sg", cache_dir=tmp_path)
    assert seen["url"] == "https://rdap.sgnic.sg/rdap/domain/lazada.sg"
    assert out["domain"] == "lazada.sg" and out["registrar"] == "MarkMonitor Inc."


def test_registration_returns_none_for_unknown_tld_or_error(monkeypatch, tmp_path):
    monkeypatch.setattr(rdap, "_bootstrap_memo", {"sg": "https://rdap.sgnic.sg/rdap/"})
    monkeypatch.setattr(rdap.requests, "get", lambda *a, **k: _Resp(404, {}))
    assert rdap.registration("example.zz", cache_dir=tmp_path) is None
    assert rdap.registration("missing.sg", cache_dir=tmp_path) is None


def test_bootstrap_file_is_parsed(monkeypatch, tmp_path):
    monkeypatch.setattr(rdap, "_bootstrap_memo", None)
    boot = {"services": [[["shop", "sony"], ["https://rdap.gmoregistry.net/rdap/"]],
                         [["xyz"], ["http://insecure.example/", "https://rdap.centralnic.com/xyz"]]]}
    (tmp_path / "rdap_bootstrap.json").write_text(__import__("json").dumps(boot), encoding="utf-8")
    servers = rdap._load_bootstrap(tmp_path)
    assert servers["shop"] == "https://rdap.gmoregistry.net/rdap/"
    assert servers["xyz"] == "https://rdap.centralnic.com/xyz/"
    assert servers["sg"].startswith("https://")  # the built-in fallback survives
    monkeypatch.setattr(rdap, "_bootstrap_memo", None)

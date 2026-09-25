import requests

from usi.lookups import crtsh
from usi.models import Severity


class FakeResp:
    def __init__(self, status=200, text='[{"id": 1}]', payload=None):
        self.status_code = status
        self.text = text
        self._payload = [{"id": 1}] if payload is None else payload

    def json(self):
        return self._payload


def test_cert_exists_true(monkeypatch):
    monkeypatch.setattr(crtsh.requests, "get", lambda *a, **k: FakeResp())
    assert crtsh.has_certificate("paypl.com") is True


def test_no_certs_false(monkeypatch):
    monkeypatch.setattr(crtsh.requests, "get", lambda *a, **k: FakeResp(text="[]", payload=[]))
    assert crtsh.has_certificate("paypl.com") is False


def test_empty_body_false(monkeypatch):
    monkeypatch.setattr(crtsh.requests, "get", lambda *a, **k: FakeResp(text="  "))
    assert crtsh.has_certificate("paypl.com") is False


def test_http_error_and_network_failure_are_unknown_not_false(monkeypatch):
    monkeypatch.setattr(crtsh.requests, "get", lambda *a, **k: FakeResp(status=503))
    assert crtsh.has_certificate("x.com") is None

    def boom(*a, **k):
        raise requests.Timeout("slow")
    monkeypatch.setattr(crtsh.requests, "get", boom)
    assert crtsh.has_certificate("x.com") is None


def test_lookalike_signal_is_about_the_investigated_host_and_medium(monkeypatch):
    # Regression: this used to check ~10 arbitrary *other* variants of the
    # brand's domain and report CRITICAL if any had a cert - attributing
    # unrelated domains' certificates to the URL being judged.
    asked = []
    monkeypatch.setattr(crtsh, "has_certificate", lambda d: asked.append(d) or True)
    sigs = crtsh.check_lookalike_host("paypl-login.top")
    assert asked == ["paypl-login.top"]
    assert len(sigs) == 1
    assert sigs[0].code == "lookalike_has_cert"
    assert sigs[0].severity == Severity.MEDIUM
    assert sigs[0].evidence["domain"] == "paypl-login.top"


def test_no_signal_when_no_cert_or_lookup_failed(monkeypatch):
    monkeypatch.setattr(crtsh, "has_certificate", lambda d: False)
    assert crtsh.check_lookalike_host("x.top") == []
    monkeypatch.setattr(crtsh, "has_certificate", lambda d: None)
    assert crtsh.check_lookalike_host("x.top") == []

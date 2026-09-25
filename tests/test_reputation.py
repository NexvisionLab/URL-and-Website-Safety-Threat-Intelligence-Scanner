import pytest
import requests

from usi.models import Severity
from usi.reputation import abuseipdb, safe_browsing, urlscan, virustotal
from usi.reputation.base import ReputationClient


class FakeResp:
    def __init__(self, status_code=200, payload=None, raise_json=False):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self._raise_json = raise_json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}")

    def json(self):
        if self._raise_json:
            raise ValueError("bad json")
        return self._payload


def test_base_client_check_is_abstract():
    with pytest.raises(NotImplementedError):
        ReputationClient("k", True).check("http://x.com", "x.com")


def test_unconfigured_clients_return_none():
    assert safe_browsing.SafeBrowsingClient("", True).check("http://x.com", "x.com") is None
    assert virustotal.VirusTotalClient("key", False).check("http://x.com", "x.com") is None
    assert abuseipdb.AbuseIPDBClient("", True).check("http://x.com", "x.com") is None
    assert urlscan.UrlscanClient("", False).check("http://x.com", "x.com") is None


# --- Safe Browsing ---

def test_safe_browsing_match_is_critical(monkeypatch):
    monkeypatch.setattr(safe_browsing.requests, "post",
                        lambda *a, **k: FakeResp(payload={"matches": [{"threatType": "MALWARE"}]}))
    sig = safe_browsing.SafeBrowsingClient("k", True).check("http://bad.top", "bad.top")
    assert sig.code == "safe_browsing_match"
    assert sig.severity == Severity.CRITICAL


def test_safe_browsing_clean(monkeypatch):
    monkeypatch.setattr(safe_browsing.requests, "post", lambda *a, **k: FakeResp(payload={}))
    sig = safe_browsing.SafeBrowsingClient("k", True).check("http://ok.com", "ok.com")
    assert sig.code == "safe_browsing_clean"
    assert sig.severity == Severity.INFO


def test_safe_browsing_http_error_is_unavailable_not_clean(monkeypatch):
    monkeypatch.setattr(safe_browsing.requests, "post", lambda *a, **k: FakeResp(status_code=403))
    sig = safe_browsing.SafeBrowsingClient("k", True).check("http://x.com", "x.com")
    assert sig.code == "safe_browsing_unavailable"


# --- VirusTotal ---

def _vt(malicious=0, suspicious=0):
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": malicious, "suspicious": suspicious}}}}


def test_virustotal_malicious(monkeypatch):
    monkeypatch.setattr(virustotal.requests, "get", lambda *a, **k: FakeResp(payload=_vt(malicious=3)))
    sig = virustotal.VirusTotalClient("k", True).check("http://x.com", "x.com")
    assert sig.code == "virustotal_malicious"
    assert sig.severity == Severity.CRITICAL


def test_virustotal_suspicious_only_is_medium(monkeypatch):
    monkeypatch.setattr(virustotal.requests, "get", lambda *a, **k: FakeResp(payload=_vt(suspicious=2)))
    sig = virustotal.VirusTotalClient("k", True).check("http://x.com", "x.com")
    assert sig.code == "virustotal_suspicious"
    assert sig.severity == Severity.MEDIUM


def test_virustotal_clean(monkeypatch):
    monkeypatch.setattr(virustotal.requests, "get", lambda *a, **k: FakeResp(payload=_vt()))
    assert virustotal.VirusTotalClient("k", True).check("http://x.com", "x.com").code == "virustotal_clean"


def test_virustotal_404_is_unseen_info(monkeypatch):
    monkeypatch.setattr(virustotal.requests, "get", lambda *a, **k: FakeResp(status_code=404))
    sig = virustotal.VirusTotalClient("k", True).check("http://x.com", "x.com")
    assert sig.code == "virustotal_unseen"


def test_virustotal_bad_json_is_unavailable(monkeypatch):
    monkeypatch.setattr(virustotal.requests, "get", lambda *a, **k: FakeResp(raise_json=True))
    assert virustotal.VirusTotalClient("k", True).check("http://x.com", "x.com").code == "virustotal_unavailable"


# --- urlscan ---

def test_urlscan_works_without_key(monkeypatch):
    monkeypatch.setattr(urlscan.requests, "get", lambda *a, **k: FakeResp(payload={"results": []}))
    sig = urlscan.UrlscanClient("", True).check("http://x.com", "x.com")
    assert sig.code == "urlscan_no_scans"


def test_urlscan_malicious_verdict(monkeypatch):
    payload = {"results": [{"page": {"verdict": "malicious"}}, {"page": {}}]}
    monkeypatch.setattr(urlscan.requests, "get", lambda *a, **k: FakeResp(payload=payload))
    sig = urlscan.UrlscanClient("", True).check("http://x.com", "x.com")
    assert sig.code == "urlscan_malicious"
    assert sig.evidence["malicious_count"] == 1


def test_urlscan_high_score_counts_as_malicious(monkeypatch):
    payload = {"results": [{"verdicts": {"overall": {"score": 80}}}]}
    monkeypatch.setattr(urlscan.requests, "get", lambda *a, **k: FakeResp(payload=payload))
    assert urlscan.UrlscanClient("", True).check("http://x.com", "x.com").code == "urlscan_malicious"


def test_urlscan_clean(monkeypatch):
    payload = {"results": [{"page": {"verdict": ""}, "verdicts": {"overall": {"score": 0}}}]}
    monkeypatch.setattr(urlscan.requests, "get", lambda *a, **k: FakeResp(payload=payload))
    assert urlscan.UrlscanClient("", True).check("http://x.com", "x.com").code == "urlscan_clean"


# --- AbuseIPDB ---

def test_abuseipdb_high_confidence(monkeypatch):
    monkeypatch.setattr(abuseipdb.socket, "gethostbyname", lambda h: "203.0.113.5")
    payload = {"data": {"abuseConfidenceScore": 90, "totalReports": 12}}
    monkeypatch.setattr(abuseipdb.requests, "get", lambda *a, **k: FakeResp(payload=payload))
    sig = abuseipdb.AbuseIPDBClient("k", True).check("http://x.com", "x.com")
    assert sig.code == "abuseipdb_high_confidence"
    assert sig.severity == Severity.HIGH


def test_abuseipdb_low_confidence(monkeypatch):
    monkeypatch.setattr(abuseipdb.socket, "gethostbyname", lambda h: "203.0.113.5")
    payload = {"data": {"abuseConfidenceScore": 3, "totalReports": 0}}
    monkeypatch.setattr(abuseipdb.requests, "get", lambda *a, **k: FakeResp(payload=payload))
    assert abuseipdb.AbuseIPDBClient("k", True).check("http://x.com", "x.com").code == "abuseipdb_low_confidence"


def test_abuseipdb_dns_failure_is_unavailable(monkeypatch):
    def boom(host):
        raise abuseipdb.socket.gaierror("no such host")
    monkeypatch.setattr(abuseipdb.socket, "gethostbyname", boom)
    assert abuseipdb.AbuseIPDBClient("k", True).check("http://x.com", "x.com").code == "abuseipdb_unavailable"

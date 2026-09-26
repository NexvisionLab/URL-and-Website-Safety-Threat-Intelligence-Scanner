import random
from datetime import datetime, timedelta, timezone

import pytest

from usi.models import Severity
from usi.shop import address

NOW = datetime(2026, 9, 26, tzinfo=timezone.utc)


@pytest.mark.parametrize("name", ["harveynorman", "limcheeguan", "tiongbahrubakery", "ongshunmugam", "cshhcoffee",
                                  "klarra", "onlewo", "ohvola", "sassandedge", "korodrogerie", "bhphotovideo"])
def test_genuine_shop_names_do_not_read_as_random(name):
    assert address.name_llr(name) > address.RANDOM_NAME_LLR
    assert address.random_name_signal(name + ".com") is None


def test_generated_names_read_as_random():
    rng = random.Random(3)
    names = ["".join(rng.choice("bcdfghjklmnpqrstvwxz") for _ in range(9)) for _ in range(50)]
    caught = sum(1 for n in names if address.random_name_signal(n + ".shop"))
    assert caught >= 45  # consonant strings of nine letters are clear-cut


def test_random_name_is_only_minor_and_skips_short_or_mixed_names():
    sig = address.random_name_signal("xkqzvbjwd.shop")
    assert sig.code == "shop_random_name" and sig.severity == Severity.LOW
    assert address.random_name_signal("xkq.shop") is None          # too short to judge
    assert address.random_name_signal("shop-xkqzvbjwd.com") is None  # not a single word


def test_certificate_branches():
    new = address.certificate_signals(NOW - timedelta(days=10), None, now=NOW)
    assert [s.code for s in new] == ["shop_cert_new"] and new[0].severity == Severity.MEDIUM
    reused = address.certificate_signals(NOW - timedelta(days=10), 3000, now=NOW)
    assert [s.code for s in reused] == ["shop_old_domain_new_site"] and reused[0].severity == Severity.LOW
    assert [s.code for s in address.certificate_signals(NOW - timedelta(days=400), None, now=NOW)] == ["shop_cert_age"]
    assert [s.code for s in address.certificate_signals(False, None, now=NOW)] == ["shop_cert_none"]
    assert [s.code for s in address.certificate_signals(None, None, now=NOW)] == ["shop_cert_history_unavailable"]


def test_first_certificate_parses_crtsh(monkeypatch):
    class Resp:
        status_code = 200
        text = "[...]"

        def json(self):
            return [{"not_before": "2026-08-29T06:50:04"}, {"not_before": "2025-01-02T00:00:00"}, {"not_before": None}]
    monkeypatch.setattr(address.requests, "get", lambda *a, **k: Resp())
    assert address.first_certificate("x.com") == datetime(2025, 1, 2, tzinfo=timezone.utc)


def test_crtsh_down_is_none_not_false(monkeypatch):
    def boom(*a, **k):
        raise address.requests.ConnectionError()
    monkeypatch.setattr(address.requests, "get", boom)
    assert address.first_certificate("x.com") is None


def test_known_fake_shop_hosting_is_exact_address_only():
    hit = address.hosting_signals(["207.244.126.19"])
    assert hit[0].code == "shop_known_fake_hosting" and "Malwarebytes" in hit[0].message
    assert address.hosting_signals(["207.244.126.20"]) == []  # same range, different customer
    assert address.hosting_signals([]) == []

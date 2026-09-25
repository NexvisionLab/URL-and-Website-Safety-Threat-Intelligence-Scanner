import sqlite3
from datetime import date, timedelta

import pytest

from usi.models import Severity
from usi.shop import identity


@pytest.mark.parametrize("text,expected", [
    ("Copyright 2025 Foo Pte. Ltd. (201912345K). All rights reserved", ["201912345K"]),
    ("UEN: 53012345D", ["53012345D"]),
    ("Co. Reg. No.: 199901234A", ["199901234A"]),
    ("Company Registration Number 201012345Z", ["201012345Z"]),
    ("SKU 12345678X, order 2019123456A", []),
    ("UEN: 280012345K", []),  # a year that hasn't happened
])
def test_find_uens(text, expected):
    assert identity.find_uens([text]) == expected


def test_looks_singaporean():
    assert identity.looks_singaporean("shop.sg", [""], [], [])
    assert identity.looks_singaporean("shop.com", ["Now only S$ 19.90"], [], [])
    assert identity.looks_singaporean("shop.com", [""], ["+65 6123 4567"], [])
    assert not identity.looks_singaporean("shop.com", ["Ships to Singapore"], [], [])


def found(status="Registered", name="ACME TRADING PTE. LTD.", registered="2015-04-30"):
    return {"found": True, "uen": "201511638H", "name": name, "status": status, "entity_type": "Local Company",
            "registered": registered, "postal_code": "079903"}


def codes(signals):
    return {s.code: s.severity for s in signals}


def test_uen_not_in_register_is_high():
    sig = codes(identity.signals(["201511638H"], {"201511638H": {"found": False}}, True, "acme"))
    assert sig == {"shop_uen_not_found": Severity.HIGH}


def test_uen_numbered_this_year_and_missing_is_only_low():
    uen = f"{date.today().year}12345K"
    sig = codes(identity.signals([uen], {uen: {"found": False}}, True, "acme"))
    assert sig == {"shop_uen_not_found": Severity.LOW}


def test_deregistered_is_high():
    sig = codes(identity.signals(["201511638H"], {"201511638H": found(status="Deregistered")}, True, "acme"))
    assert sig == {"shop_uen_deregistered": Severity.HIGH}


def test_verified_and_named_on_the_site():
    sig = codes(identity.signals(["201511638H"], {"201511638H": found()}, True, "Welcome to Acme Trading"))
    assert sig == {"shop_uen_verified": Severity.INFO}


def test_verified_but_belongs_to_someone_else():
    sig = codes(identity.signals(["201511638H"], {"201511638H": found(name="ZEPHYR LOGISTICS PTE. LTD.")},
                                 True, "Welcome to Budget Sneakers"))
    assert sig["shop_uen_name_mismatch"] == Severity.LOW


def test_recently_registered_company():
    recent = (date.today() - timedelta(days=20)).isoformat()
    sig = codes(identity.signals(["201511638H"], {"201511638H": found(registered=recent)}, True, "acme"))
    assert sig["shop_uen_recent"] == Severity.LOW


def test_register_unreachable_is_info():
    assert codes(identity.signals(["201511638H"], {"201511638H": None}, True, "")) == {
        "shop_uen_unavailable": Severity.INFO}


def test_singaporean_shop_without_uen():
    assert codes(identity.signals([], {}, True, "")) == {"shop_sg_no_uen": Severity.LOW}
    assert identity.signals([], {}, False, "") == []


def test_lookup_prefers_local_register(monkeypatch, tmp_path):
    db = tmp_path / "acra.sqlite3"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE entities (uen TEXT PRIMARY KEY, entity_name TEXT, uen_status_desc TEXT, "
                 "entity_type_desc TEXT, uen_issue_date TEXT, reg_postal_code TEXT)")
    conn.execute("INSERT INTO entities VALUES ('201511638H','ACME PTE. LTD.','Registered','Local Company','2015-04-30','079903')")
    conn.commit()
    conn.close()
    monkeypatch.setenv(identity.LOCAL_DB_ENV, str(db))
    monkeypatch.setattr(identity, "_lookup_api", lambda uen: pytest.fail("the API must not be called"))
    assert identity.lookup("201511638H", str(tmp_path / "c.sqlite3"))["name"] == "ACME PTE. LTD."
    assert identity.lookup("209912345A", str(tmp_path / "c.sqlite3")) == {"found": False, "uen": "209912345A"}


def test_api_lookup_is_cached(monkeypatch, tmp_path):
    monkeypatch.setenv(identity.LOCAL_DB_ENV, str(tmp_path / "missing.sqlite3"))
    calls = []

    class Resp:
        status_code = 200

        def json(self):
            return {"success": True, "result": {"records": [
                {"uen": "201511638H", "entity_name": "ACME PTE. LTD.", "uen_status_desc": "Registered",
                 "entity_type_desc": "Local Company", "uen_issue_date": "2015-04-30", "reg_postal_code": "079903"}]}}

    def fake_get(url, timeout, headers, params):
        calls.append(params)
        return Resp()
    monkeypatch.setattr(identity.requests, "get", fake_get)
    cache_path = str(tmp_path / "c.sqlite3")
    assert identity.lookup("201511638H", cache_path)["status"] == "Registered"
    assert identity.lookup("201511638H", cache_path)["status"] == "Registered"
    assert len(calls) == 1 and '"201511638H"' in calls[0]["filters"]


def test_api_rate_limit_means_unavailable(monkeypatch, tmp_path):
    monkeypatch.setenv(identity.LOCAL_DB_ENV, str(tmp_path / "missing.sqlite3"))

    class Resp:
        status_code = 429

        def json(self):
            return {"code": 24, "name": "TOO_MANY_REQUESTS"}
    monkeypatch.setattr(identity.requests, "get", lambda *a, **k: Resp())
    assert identity.lookup("201511638H", str(tmp_path / "c.sqlite3")) is None

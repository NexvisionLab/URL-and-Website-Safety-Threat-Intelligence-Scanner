import time

from usi import cache


def test_set_then_get_returns_value(tmp_path):
    db_path = str(tmp_path / "test_cache.sqlite3")
    cache.set(db_path, "https://example.com", {"verdict": "Likely Safe"})
    result = cache.get(db_path, "https://example.com", ttl_hours=24)
    assert result == {"verdict": "Likely Safe"}


def test_get_missing_returns_none(tmp_path):
    db_path = str(tmp_path / "test_cache.sqlite3")
    assert cache.get(db_path, "https://never-cached.example", ttl_hours=24) is None


def test_normalize_url_is_case_and_slash_insensitive():
    assert cache.normalize_url("HTTPS://Example.COM/") == cache.normalize_url("https://example.com")


def test_expired_entry_returns_none(tmp_path):
    db_path = str(tmp_path / "test_cache.sqlite3")
    cache.set(db_path, "https://example.com", {"verdict": "Likely Safe"})
    # ttl_hours=0 means anything already stored is immediately "expired"
    time.sleep(0.01)
    assert cache.get(db_path, "https://example.com", ttl_hours=0) is None


def test_set_overwrites_existing_entry(tmp_path):
    db_path = str(tmp_path / "test_cache.sqlite3")
    cache.set(db_path, "https://example.com", {"verdict": "Likely Safe"})
    cache.set(db_path, "https://example.com", {"verdict": "Suspicious"})
    result = cache.get(db_path, "https://example.com", ttl_hours=24)
    assert result == {"verdict": "Suspicious"}


def test_list_all_returns_every_entry(tmp_path):
    db_path = str(tmp_path / "test_cache.sqlite3")
    cache.set(db_path, "https://a.com", {"verdict": "Likely Safe"})
    cache.set(db_path, "https://b.com", {"verdict": "Suspicious"})
    results = cache.list_all(db_path)
    assert len(results) == 2
    assert {r["verdict"] for r in results} == {"Likely Safe", "Suspicious"}


def test_list_all_empty_cache_returns_empty_list(tmp_path):
    db_path = str(tmp_path / "test_cache.sqlite3")
    assert cache.list_all(db_path) == []


def test_list_all_respects_since_hours_filter(tmp_path):
    db_path = str(tmp_path / "test_cache.sqlite3")
    cache.set(db_path, "https://a.com", {"verdict": "Likely Safe"})
    # since_hours=0 excludes everything already stored (nothing checked
    # "within the last 0 hours" from this exact instant onward)
    assert cache.list_all(db_path, since_hours=0) == []
    assert len(cache.list_all(db_path, since_hours=24)) == 1

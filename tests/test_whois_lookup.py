from datetime import datetime, timedelta

from usi.lookups import whois_lookup


class FakeWhoisResult:
    def __init__(self, creation_date=None, expiration_date=None, registrar=None, text=""):
        self.creation_date = creation_date
        self.expiration_date = expiration_date
        self.registrar = registrar
        self.text = text


def test_skip_returns_unavailable_signal():
    signals = whois_lookup.lookup("somehost.onion", skip=True)
    assert len(signals) == 1
    assert signals[0].code == "whois_unavailable"


def test_lookup_failure_does_not_crash(monkeypatch):
    def raise_error(host):
        raise Exception("No match for the domain.")
    monkeypatch.setattr(whois_lookup.whois, "whois", raise_error)
    signals = whois_lookup.lookup("nonexistent-test.com")
    assert len(signals) == 1
    assert signals[0].code == "whois_unavailable"
    assert "No match" in signals[0].message


def test_long_whois_error_is_truncated(monkeypatch):
    def raise_error(host):
        raise Exception("A" * 5000)
    monkeypatch.setattr(whois_lookup.whois, "whois", raise_error)
    signals = whois_lookup.lookup("test.com")
    assert len(signals[0].message) < 300


def test_young_domain_flagged(monkeypatch):
    result = FakeWhoisResult(
        creation_date=datetime.now() - timedelta(days=5),
        registrar="Some Registrar",
    )
    monkeypatch.setattr(whois_lookup.whois, "whois", lambda host: result)
    signals = whois_lookup.lookup("test.com")
    codes = {s.code for s in signals}
    assert "young_domain" in codes


def test_old_domain_not_flagged_as_young(monkeypatch):
    result = FakeWhoisResult(
        creation_date=datetime.now() - timedelta(days=3650),
        registrar="Some Registrar",
    )
    monkeypatch.setattr(whois_lookup.whois, "whois", lambda host: result)
    signals = whois_lookup.lookup("test.com")
    codes = {s.code for s in signals}
    assert "young_domain" not in codes
    assert "domain_age" in codes


def test_one_year_registration_period_flagged(monkeypatch):
    created = datetime.now() - timedelta(days=3650)
    result = FakeWhoisResult(
        creation_date=created,
        expiration_date=created + timedelta(days=365),
        registrar="Some Registrar",
    )
    monkeypatch.setattr(whois_lookup.whois, "whois", lambda host: result)
    signals = whois_lookup.lookup("test.com")
    codes = {s.code for s in signals}
    assert "short_registration_period" in codes


def test_multi_year_registration_period_not_flagged(monkeypatch):
    created = datetime.now() - timedelta(days=3650)
    result = FakeWhoisResult(
        creation_date=created,
        expiration_date=created + timedelta(days=365 * 10),
        registrar="Some Registrar",
    )
    monkeypatch.setattr(whois_lookup.whois, "whois", lambda host: result)
    signals = whois_lookup.lookup("test.com")
    codes = {s.code for s in signals}
    assert "short_registration_period" not in codes


def test_short_registration_signal_is_info_severity(monkeypatch):
    created = datetime.now() - timedelta(days=3650)
    result = FakeWhoisResult(
        creation_date=created,
        expiration_date=created + timedelta(days=365),
        registrar="Some Registrar",
    )
    monkeypatch.setattr(whois_lookup.whois, "whois", lambda host: result)
    signals = whois_lookup.lookup("test.com")
    sig = next(s for s in signals if s.code == "short_registration_period")
    from usi.models import Severity
    assert sig.severity == Severity.INFO


def test_missing_expiration_date_does_not_crash(monkeypatch):
    result = FakeWhoisResult(
        creation_date=datetime.now() - timedelta(days=3650),
        expiration_date=None,
        registrar="Some Registrar",
    )
    monkeypatch.setattr(whois_lookup.whois, "whois", lambda host: result)
    signals = whois_lookup.lookup("test.com")
    codes = {s.code for s in signals}
    assert "short_registration_period" not in codes


def test_privacy_protected_flagged(monkeypatch):
    # Regression: python-whois's .text is typically a plain string, not a
    # list - the original code iterated it character-by-character and
    # rejoined with spaces ("REDACTED" -> "R E D A C T E D"), silently
    # breaking this check for every real-world lookup where .text is a
    # string. Caught by this exact test while adding the unrelated
    # expiration-date feature.
    result = FakeWhoisResult(
        creation_date=datetime.now() - timedelta(days=3650),
        registrar="Some Registrar",
        text="Registrant: REDACTED FOR PRIVACY",
    )
    monkeypatch.setattr(whois_lookup.whois, "whois", lambda host: result)
    signals = whois_lookup.lookup("test.com")
    codes = {s.code for s in signals}
    assert "privacy_protected" in codes


def test_privacy_protected_flagged_when_text_is_a_list(monkeypatch):
    # Some WHOIS server responses genuinely give python-whois a list of
    # strings (multiple servers queried) - confirm that shape still works
    # correctly alongside the plain-string shape above.
    result = FakeWhoisResult(
        creation_date=datetime.now() - timedelta(days=3650),
        registrar="Some Registrar",
        text=["Registrant: REDACTED FOR PRIVACY", "Some other server block"],
    )
    monkeypatch.setattr(whois_lookup.whois, "whois", lambda host: result)
    signals = whois_lookup.lookup("test.com")
    codes = {s.code for s in signals}
    assert "privacy_protected" in codes


def test_no_usable_data_returns_unavailable(monkeypatch):
    result = FakeWhoisResult(creation_date=None, registrar=None)
    monkeypatch.setattr(whois_lookup.whois, "whois", lambda host: result)
    signals = whois_lookup.lookup("test.com")
    assert len(signals) == 1
    assert signals[0].code == "whois_unavailable"

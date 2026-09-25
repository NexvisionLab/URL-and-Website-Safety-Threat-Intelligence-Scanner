from usi.models import Severity, Signal
from usi.verdict import aggregator


def sig(severity, code="test_code", source="test"):
    return Signal(source=source, code=code, severity=severity, message="test")


def test_no_signals_is_likely_safe():
    report = aggregator.rate([])
    assert report.verdict == "Likely Safe"


def test_critical_signal_is_likely_malicious():
    report = aggregator.rate([sig(Severity.CRITICAL), sig(Severity.INFO)])
    assert report.verdict == "Likely Malicious"


def test_high_signal_is_suspicious():
    report = aggregator.rate([sig(Severity.HIGH)])
    assert report.verdict == "Suspicious"


def test_single_medium_signal_does_not_move_verdict():
    report = aggregator.rate([sig(Severity.MEDIUM)])
    assert report.verdict == "Likely Safe"


def test_two_medium_signals_is_suspicious():
    report = aggregator.rate([sig(Severity.MEDIUM, code="a"), sig(Severity.MEDIUM, code="b")])
    assert report.verdict == "Suspicious"


def test_only_unavailable_signals_is_unknown():
    report = aggregator.rate([
        sig(Severity.INFO, code="fetch_failed"),
        sig(Severity.INFO, code="whois_unavailable"),
    ])
    assert report.verdict == "Unknown"


def test_unavailable_plus_low_evidence_is_not_unknown():
    report = aggregator.rate([
        sig(Severity.INFO, code="fetch_failed"),
        sig(Severity.LOW, code="suspicious_tld"),
    ])
    assert report.verdict == "Likely Safe"


def test_verdict_carries_full_signal_list():
    signals = [sig(Severity.HIGH), sig(Severity.INFO)]
    report = aggregator.rate(signals)
    assert report.signals == signals


def test_critical_beats_high():
    report = aggregator.rate([sig(Severity.HIGH), sig(Severity.CRITICAL)])
    assert report.verdict == "Likely Malicious"


def test_skipped_layer_alone_is_not_unknown():
    # A deliberate --no-fetch/--offline skip is not a failure - must not
    # push a clean result to "Unknown".
    report = aggregator.rate([sig(Severity.INFO, code="fetch_skipped")])
    assert report.verdict == "Likely Safe"


def test_clean_info_evidence_alongside_a_skip_is_likely_safe():
    # Regression: WHOIS/TLS succeeding with only INFO-level findings, plus
    # a deliberately-skipped fetch, must not read as "no evidence".
    report = aggregator.rate([
        sig(Severity.INFO, code="fetch_skipped"),
        sig(Severity.INFO, code="domain_age"),
        sig(Severity.INFO, code="registrar"),
        sig(Severity.INFO, code="tls_cert_info"),
    ])
    assert report.verdict == "Likely Safe"


def test_reputation_client_unavailable_code_recognized_as_failure():
    report = aggregator.rate([sig(Severity.INFO, code="virustotal_unavailable")])
    assert report.verdict == "Unknown"


# --- 2026-09-25: an unresolved brand lookalike must not read as safe ---

def _lookalike(whole_label):
    return Signal(source="typosquat", code="combosquat_keyword_match", severity=Severity.MEDIUM, message="x",
                  evidence={"brand_is_whole_label": whole_label})


def test_brand_lookalike_whose_page_could_not_load_is_suspicious():
    report = aggregator.rate([_lookalike(True), sig(Severity.INFO, code="fetch_failed", source="fetch")])
    assert report.verdict == "Suspicious"


def test_brand_lookalike_that_loaded_stays_as_before():
    assert aggregator.rate([_lookalike(True)]).verdict == "Likely Safe"


def test_substring_only_lookalike_with_a_failed_fetch_stays_as_before():
    report = aggregator.rate([_lookalike(False), sig(Severity.INFO, code="fetch_failed", source="fetch")])
    assert report.verdict == "Likely Safe"

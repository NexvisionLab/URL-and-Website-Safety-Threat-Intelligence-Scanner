from usi.models import InvestigationResult, Severity, Signal, VerdictReport
from usi.output import report


def make_result(url, host, verdict, signals=None, skipped=None):
    return InvestigationResult(
        url=url, host=host, is_onion=False, from_cache=False,
        checked_at="2026-09-23T12:00:00+00:00",
        verdict=VerdictReport(verdict=verdict, signals=signals or []),
        skipped_layers=skipped or [],
    )


def test_markdown_single_result_contains_url_and_verdict():
    result = make_result("https://evil.top", "evil.top", "Likely Malicious", signals=[
        Signal(source="favicon", code="favicon_matches_brand", severity=Severity.CRITICAL,
               message="Favicon matches DHL."),
    ])
    md = report.build_markdown([result])
    assert "https://evil.top" in md
    assert "Likely Malicious" in md
    assert "favicon" in md
    assert "Favicon matches DHL." in md
    assert "Disclaimer" in md


def test_markdown_multiple_results_has_summary_table():
    results = [
        make_result("https://a.com", "a.com", "Likely Safe"),
        make_result("https://b.top", "b.top", "Suspicious", signals=[
            Signal(source="typosquat", code="typosquat_match", severity=Severity.HIGH, message="looks fake"),
        ]),
    ]
    md = report.build_markdown(results)
    assert "## Summary" in md
    assert "https://a.com" in md
    assert "https://b.top" in md


def test_markdown_single_result_no_summary_table():
    md = report.build_markdown([make_result("https://a.com", "a.com", "Likely Safe")])
    assert "## Summary" not in md


def test_markdown_orders_by_verdict_severity():
    results = [
        make_result("https://safe.com", "safe.com", "Likely Safe"),
        make_result("https://bad.com", "bad.com", "Likely Malicious"),
        make_result("https://mid.com", "mid.com", "Suspicious"),
    ]
    md = report.build_markdown(results)
    assert md.index("bad.com") < md.index("mid.com") < md.index("safe.com")


def test_markdown_notes_skipped_layers():
    result = make_result("https://x.com", "x.com", "Unknown", skipped=["whois", "reputation"])
    md = report.build_markdown([result])
    assert "Not checked" in md
    assert "whois" in md


def test_html_single_result_contains_url_and_verdict():
    result = make_result("https://evil.top", "evil.top", "Likely Malicious", signals=[
        Signal(source="favicon", code="favicon_matches_brand", severity=Severity.CRITICAL,
               message="Favicon matches DHL."),
    ])
    html = report.build_html([result])
    assert "<html" in html
    assert "evil.top" in html
    assert "Likely Malicious" in html
    assert "verdict-malicious" in html


def test_html_escapes_special_characters():
    result = make_result("https://x.com", "x.com", "Suspicious", signals=[
        Signal(source="test", code="test", severity=Severity.HIGH, message="<script>alert(1)</script>"),
    ])
    html = report.build_html([result])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_markdown_no_notable_signals_says_so():
    result = make_result("https://clean.com", "clean.com", "Likely Safe")
    md = report.build_markdown([result])
    assert "No notable signals." in md


def test_markdown_verdict_has_color_icon():
    result = make_result("https://evil.top", "evil.top", "Likely Malicious")
    md = report.build_markdown([result])
    assert "\U0001F534 Likely Malicious" in md  # red circle


def test_markdown_severity_has_color_icon():
    result = make_result("https://evil.top", "evil.top", "Likely Malicious", signals=[
        Signal(source="favicon", code="favicon_matches_brand", severity=Severity.CRITICAL,
               message="Favicon matches DHL."),
    ])
    md = report.build_markdown([result])
    assert "\U0001F534 CRITICAL" in md  # red circle


def test_markdown_includes_verdict_legend():
    md = report.build_markdown([make_result("https://a.com", "a.com", "Likely Safe")])
    assert "Likely Malicious" in md
    assert "\U0001F7E2 Likely Safe" in md  # green circle, from the legend line


def test_html_verdict_badge_has_color_icon():
    result = make_result("https://evil.top", "evil.top", "Likely Malicious")
    html = report.build_html([result])
    assert "\U0001F534 Likely Malicious" in html


def test_html_finding_row_has_severity_class_and_icon():
    result = make_result("https://evil.top", "evil.top", "Likely Malicious", signals=[
        Signal(source="favicon", code="favicon_matches_brand", severity=Severity.CRITICAL,
               message="Favicon matches DHL."),
    ])
    html = report.build_html([result])
    assert "row-CRITICAL" in html
    assert "\U0001F534 CRITICAL" in html


def test_html_result_card_has_verdict_border_class():
    result = make_result("https://evil.top", "evil.top", "Likely Malicious")
    html = report.build_html([result])
    assert "result-card verdict-malicious" in html

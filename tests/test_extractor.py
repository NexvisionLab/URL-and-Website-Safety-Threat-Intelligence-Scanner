from usi.content import clickfix, extractor


def extract(html, base="http://example.com/page", final=None):
    return extractor.extract(html, base, 200, final or base)


def test_title_and_visible_text_extracted_scripts_and_styles_dropped():
    ex = extract("<html><head><title> Hello </title><style>p{color:red}</style></head>"
                 "<body><script>var secret=1</script><p>Visible   text</p></body></html>")
    assert ex.title == "Hello"
    assert ex.text == "Hello Visible text"  # whitespace collapsed
    assert "secret" not in ex.text and "color" not in ex.text


def test_missing_title_is_none():
    assert extract("<html><body>x</body></html>").title is None


def test_password_field_detected():
    assert extract('<form><input type="password" name="p"></form>').has_password_field is True
    assert extract('<form><input type="text"></form>').has_password_field is False


def test_form_actions_resolved_against_final_url():
    ex = extract('<form action="/login"></form><form action="https://evil.top/x"></form><form></form>',
                 base="http://a.com/", final="https://a.com/page")
    assert ex.form_actions == ["https://a.com/login", "https://evil.top/x", "https://a.com/page"]


def test_only_external_links_collected_and_capped():
    links = "".join(f'<a href="https://other{i}.com/">x</a>' for i in range(30))
    ex = extract('<a href="/local">l</a>' + links, base="http://a.com/")
    assert all("a.com" not in u for u in ex.external_links)
    assert len(ex.external_links) == 20


def test_empty_and_garbage_html_do_not_crash():
    assert extract("").text == ""
    assert extract("\x00\x01 not html <<<").reachable is True


def test_long_pages_are_not_truncated_so_instructions_cannot_hide_below_filler():
    # Regression: text was cut at 4000 chars, so a ClickFix instruction
    # placed after ~8 KB of filler was never seen by the pattern checks.
    html = ("<html><body><p>" + "lorem ipsum dolor sit amet " * 300 + "</p>"
            "<p>Verify you are human: press Win + R and paste the following command.</p></body></html>")
    ex = extract(html)
    assert len(ex.text) > 4000
    sig = clickfix.check(ex.text, html)
    assert sig is not None and sig.code == "clickfix_instruction_detected"

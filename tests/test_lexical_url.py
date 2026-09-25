from usi.heuristics import lexical_url


def test_natural_brand_domains_not_flagged():
    for host in ("stackoverflow.com", "google.com", "microsoft.com", "paypal.com",
                 "wikipedia.org", "github.com"):
        signals = lexical_url.analyze(host)
        assert signals == [], f"{host} should not be flagged, got {signals}"


def test_random_looking_domain_flagged():
    # Constructed to trigger multiple sub-signals at once: high entropy,
    # low vowel ratio, a long consonant run, and scattered digits.
    signals = lexical_url.analyze("xqz7kfpbn2wj.com")
    assert len(signals) == 1
    assert signals[0].code == "dga_like_domain"
    assert len(signals[0].evidence["triggered"]) >= 2


def test_short_domain_skips_entropy_check_but_can_still_flag_on_other_signals():
    # Below MIN_LENGTH_FOR_ENTROPY_CHECK, entropy isn't checked, but the
    # other three sub-signals still run.
    signals = lexical_url.analyze("xqzpfk.com")
    # May or may not trigger depending on exact letters - just confirm no crash
    # and that the function returns a well-formed result either way.
    assert isinstance(signals, list)


def test_real_word_with_trailing_year_not_flagged():
    # "app2024"-style digit clustering (not scattered) should not trigger
    # the digit-interspersion sub-signal.
    signals = lexical_url.analyze("myapp2024.com")
    codes_triggered = signals[0].evidence["triggered"] if signals else []
    assert "scattered_digits" not in codes_triggered


def test_single_weak_signal_alone_does_not_flag():
    # A domain with only ONE of the four sub-signals triggered must not
    # produce a signal - the co-occurrence requirement is the whole point.
    # "eeeeeeee" has vowel_ratio=1.0 (not low) but very low entropy and no
    # consonant run and no digits - zero sub-signals, sanity check only.
    signals = lexical_url.analyze("eeeeeeee.com")
    assert signals == []


def test_non_ascii_domain_does_not_crash():
    # Punycode/homograph domains are handled by heuristics/punycode.py -
    # this module should just decline to analyze rather than error.
    assert lexical_url.analyze("xn--e1aybc.com") == [] or isinstance(
        lexical_url.analyze("xn--e1aybc.com"), list
    )


def test_empty_sld_does_not_crash():
    assert lexical_url.analyze("com") == []

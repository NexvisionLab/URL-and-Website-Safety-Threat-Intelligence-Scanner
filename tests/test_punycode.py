from usi.heuristics import punycode


def test_plain_ascii_host_no_signal():
    assert punycode.run_all("example.com") == []


def test_mixed_script_homograph_flagged():
    # 'аpple.com' with a Cyrillic 'а' (U+0430) instead of Latin 'a', encoded as punycode
    import idna
    cyrillic_a = "а"
    label = cyrillic_a + "pple"
    encoded = idna.encode(label).decode("ascii")
    host = f"{encoded}.com"
    signals = punycode.run_all(host)
    assert len(signals) == 1
    assert signals[0].code == "mixed_script_homograph"


def test_single_script_punycode_is_info_only():
    # A genuinely non-English domain in one script (e.g. pure Cyrillic) should
    # not be flagged as a homograph attack - just noted as INFO.
    import idna
    label = "пример"  # "пример" (Russian for "example"), all Cyrillic
    encoded = idna.encode(label).decode("ascii")
    host = f"{encoded}.com"
    signals = punycode.run_all(host)
    assert len(signals) == 1
    assert signals[0].code == "punycode_present"
    from usi.models import Severity
    assert signals[0].severity == Severity.INFO

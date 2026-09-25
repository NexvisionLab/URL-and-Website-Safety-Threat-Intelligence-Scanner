"""IDN/punycode decode + mixed-script (homograph) detection. A legitimate
domain is essentially always written in one Unicode script; a domain
mixing e.g. Latin and Cyrillic letters in the same label is the classic
homograph-attack signature (Cyrillic 'а' U+0430 looks identical to
Latin 'a' U+0061 in most fonts)."""
import unicodedata

import idna

from ..models import Severity, Signal

# Coarse script buckets: unicodedata.name() strings start with the script
# name for the scripts realistically seen in homograph attacks. Digits/
# punctuation/COMMON characters are excluded from the "scripts seen" set
# below since they're script-neutral.
_SCRIPT_PREFIXES = ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW")


def _char_script(ch: str) -> "str | None":
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    for prefix in _SCRIPT_PREFIXES:
        if name.startswith(prefix):
            return prefix
    return None


def decode_punycode_labels(host: str) -> "list[tuple[str, str]]":
    """Returns [(ascii_label, decoded_unicode_label), ...] for every
    xn-- label in the host. Labels that fail to decode are skipped."""
    decoded = []
    for label in host.split("."):
        if not label.lower().startswith("xn--"):
            continue
        try:
            decoded.append((label, idna.decode(label)))
        except idna.IDNAError:
            continue
    return decoded


def check_mixed_script(host: str) -> "Signal | None":
    labels = decode_punycode_labels(host)
    # Also check any label that's already non-ASCII (IDNA-aware clients
    # may present the decoded form directly rather than xn--).
    plain_unicode_labels = [
        (label, label) for label in host.split(".")
        if any(ord(c) > 127 for c in label) and not label.lower().startswith("xn--")
    ]
    for ascii_label, unicode_label in labels + plain_unicode_labels:
        scripts_seen = {
            _char_script(ch) for ch in unicode_label if _char_script(ch)
        }
        if len(scripts_seen) > 1:
            return Signal(
                source="punycode",
                code="mixed_script_homograph",
                severity=Severity.HIGH,
                message=(
                    f"The label '{unicode_label}' (encoded as '{ascii_label}') "
                    f"mixes {', '.join(sorted(scripts_seen))} characters - a "
                    "classic homograph-attack technique to visually impersonate "
                    "a Latin-script domain."
                ),
                evidence={"ascii_label": ascii_label, "decoded": unicode_label,
                          "scripts": sorted(scripts_seen)},
            )
    return None


def check_punycode_present(host: str) -> "Signal | None":
    """Even a single-script punycode label is worth surfacing at INFO -
    not inherently malicious (many legitimate non-English domains use
    it), but relevant context for the report."""
    labels = decode_punycode_labels(host)
    if not labels:
        return None
    decoded_str = ", ".join(f"{a} -> {u}" for a, u in labels)
    return Signal(
        source="punycode",
        code="punycode_present",
        severity=Severity.INFO,
        message=f"Domain contains internationalized (punycode) labels: {decoded_str}",
        evidence={"labels": labels},
    )


def run_all(host: str) -> "list[Signal]":
    mixed = check_mixed_script(host)
    if mixed:
        return [mixed]
    info = check_punycode_present(host)
    return [info] if info else []

"""Lexical/entropy URL classification: statistical features on the
domain string itself, independent of any named pattern - the standard
technique for detecting algorithmically-generated domains (DGA), used
by malware for command-and-control infrastructure and increasingly to
rotate phishing infrastructure too. Every other heuristic in this tool
is a named pattern (IP-literal host, known shortener, etc.); this is
the one layer that asks "does this string look randomly generated"
instead of "does this string match a known bad shape".

Four sub-signals, each individually weak and prone to false positives
alone (a short legitimate brand name can read as high-entropy by
chance; a real word can have an unlucky consonant run) - only flags
when at least two agree, mirroring crypto_drainer.py's and
verdict/aggregator.py's general "don't fire on one weak signal alone"
philosophy. Never returns anything above MEDIUM on its own; this is
corroborating evidence for the verdict aggregator to combine with
other layers, not a standalone verdict-mover."""
import math
from collections import Counter

import tldextract

from ..models import Severity, Signal

MIN_LENGTH_FOR_ENTROPY_CHECK = 8
ENTROPY_THRESHOLD_BITS = 3.5
VOWEL_RATIO_LOW_THRESHOLD = 0.15
MAX_NATURAL_CONSONANT_RUN = 4
DIGIT_INTERSPERSION_THRESHOLD = 0.2

_VOWELS = set("aeiou")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _vowel_ratio(s: str) -> "float | None":
    letters = [c for c in s if c.isalpha()]
    if not letters:
        return None
    vowels = sum(1 for c in letters if c in _VOWELS)
    return vowels / len(letters)


def _longest_consonant_run(s: str) -> int:
    longest = current = 0
    for c in s:
        if c.isalpha() and c not in _VOWELS:
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def _digit_interspersion_ratio(s: str) -> float:
    """High when digits are scattered through an otherwise-alphabetic
    label (e.g. 'x7k2q9f') rather than clustered at the end (e.g.
    'app2024', a normal word+year pattern) - scattered digits are the
    more DGA-typical shape."""
    if not s:
        return 0.0
    digit_positions = [i for i, c in enumerate(s) if c.isdigit()]
    if not digit_positions:
        return 0.0
    # Count digit-to-letter transitions as a proxy for "scattered".
    transitions = sum(
        1 for i in range(len(s) - 1)
        if s[i].isdigit() != s[i + 1].isdigit()
    )
    return transitions / len(s)


def analyze(host: str) -> "list[Signal]":
    ext = tldextract.extract(host.lower())
    sld = ext.domain
    if not sld or not sld.isascii():
        return []

    triggered = []
    evidence = {}

    if len(sld) >= MIN_LENGTH_FOR_ENTROPY_CHECK:
        entropy = _shannon_entropy(sld)
        evidence["entropy_bits"] = round(entropy, 2)
        if entropy >= ENTROPY_THRESHOLD_BITS:
            triggered.append("high_entropy")

    vowel_ratio = _vowel_ratio(sld)
    if vowel_ratio is not None:
        evidence["vowel_ratio"] = round(vowel_ratio, 2)
        if vowel_ratio <= VOWEL_RATIO_LOW_THRESHOLD:
            triggered.append("low_vowel_ratio")

    consonant_run = _longest_consonant_run(sld)
    evidence["longest_consonant_run"] = consonant_run
    if consonant_run > MAX_NATURAL_CONSONANT_RUN:
        triggered.append("long_consonant_run")

    digit_ratio = _digit_interspersion_ratio(sld)
    evidence["digit_interspersion"] = round(digit_ratio, 2)
    if digit_ratio >= DIGIT_INTERSPERSION_THRESHOLD:
        triggered.append("scattered_digits")

    if len(triggered) < 2:
        return []

    evidence["triggered"] = triggered
    return [Signal(
        source="lexical_url", code="dga_like_domain", severity=Severity.MEDIUM,
        message=(
            f"The domain name '{sld}' has statistical characteristics of an "
            f"algorithmically-generated string ({', '.join(triggered)}) rather than "
            "a natural word or brand name - a pattern common in malware "
            "command-and-control infrastructure and rotated phishing domains. "
            "Not conclusive alone; weak on short or unusual-but-real domains."
        ),
        evidence=evidence,
    )]

"""Tests the language-detection routing decision only (English vs. not),
using langdetect directly - deliberately does NOT load either embedding
model (English or multilingual), since that would make the regular test
suite pay a large one-time download/load cost. The actual cross-lingual
classification accuracy (Portuguese/French/Spanish phishing text
correctly routing to the multilingual model and matching the right
category) was verified manually during development - see classifier.py's
docstring for that record."""
from usi.content.classifier import _detect_is_english


def test_english_text_detected_as_english():
    assert _detect_is_english("Please verify your account information to continue.") is True


def test_portuguese_text_detected_as_not_english():
    assert _detect_is_english(
        "Seu pacote esta retido na alfandega. Pague a taxa para liberar a entrega."
    ) is False


def test_french_text_detected_as_not_english():
    assert _detect_is_english(
        "Votre colis est bloque en douane. Payez les frais pour le liberer."
    ) is False


def test_german_text_detected_as_not_english():
    assert _detect_is_english(
        "Ihr Paket wird zurueckgehalten. Bitte bezahlen Sie die Gebuehr."
    ) is False


def test_empty_text_defaults_to_english():
    # langdetect raises on empty/near-empty input - must default to the
    # English model rather than crash the pipeline.
    assert _detect_is_english("") is True

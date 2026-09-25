"""The site classifier must not raise a HIGH signal on the weak scores that real shops and services get.
Numbers are from 27 well-known sites fetched live on 2026-09-25 (see HIGH_CONFIDENCE in classifier.py)."""
import pytest

from usi.content import classifier
from usi.models import Severity


def _classify_with(monkeypatch, category, score):
    import sys, types
    values = [0.05] * len(classifier._category_names)
    values[classifier._category_names.index(category)] = score

    class T(list):
        def argmax(self):
            return max(range(len(self)), key=lambda i: self[i])

    fake_util = types.SimpleNamespace(cos_sim=lambda a, b: [T(values)])
    fake_st = types.ModuleType("sentence_transformers")
    fake_st.util = fake_util
    monkeypatch.setitem(sys.modules, "sentence_transformers", fake_st)
    monkeypatch.setattr(classifier, "_detect_is_english", lambda text: True)

    class M:
        def encode(self, text, convert_to_tensor=True):
            return text

    monkeypatch.setattr(classifier, "_get_model", lambda name: (M(), None))
    return classifier.classify("some page text")


@pytest.mark.parametrize("score", [0.24, 0.28, 0.34, 0.38, 0.44])
def test_scores_real_shops_get_are_low_severity_only(monkeypatch, score):
    sig = _classify_with(monkeypatch, "scam-shop", score)
    assert sig.code == "classifier_weak_resemblance"
    assert sig.severity == Severity.LOW
    assert "not a warning on its own" in sig.message


def test_a_strong_match_is_still_high(monkeypatch):
    sig = _classify_with(monkeypatch, "malware-risk", 0.57)
    assert sig.code == "classifier_risk_category"
    assert sig.severity == Severity.HIGH


def test_below_the_floor_is_benign(monkeypatch):
    sig = _classify_with(monkeypatch, "scam-shop", 0.2)
    assert sig.code == "classifier_benign"
    assert sig.severity == Severity.INFO


def test_a_low_signal_never_moves_the_verdict():
    from usi.models import Signal
    from usi.verdict import aggregator
    weak = Signal(source="classifier", code="classifier_weak_resemblance", severity=Severity.LOW, message="x")
    assert aggregator.rate([weak]).verdict == "Likely Safe"

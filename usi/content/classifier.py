"""Local, self-hosted embedding classifier for fetched page text
(sentence-transformers, cosine similarity against hand-written category
descriptions, threshold fallback).

Multilingual support: many phishing detectors are English-only, and
attackers increasingly ship localized campaigns. Rather
than translating the category descriptions into every language, this
detects whether the page text is English and, if not, switches to a
multilingual sentence-transformers encoder (same architecture family,
same English category descriptions) - cross-lingual embedding models
map semantically similar sentences close together in embedding space
regardless of language, so an English description of "a fake bank
login page" still correctly matches real Portuguese, French, or
Spanish phishing text. Spot-checked with Portuguese, French, and
Spanish phishing sentences (classified 'phishing-clone') and a
legitimate Portuguese sentence (classified 'legitimate').

Language detection is used only for this one binary decision (English
vs. not) - langdetect is known to be unreliable on short text for
distinguishing between closely related languages (e.g. Portuguese vs.
Spanish), but that doesn't matter here since either language correctly
routes to the same multilingual model. Keyword/regex-based modules
(clickfix.py, delivery_fee.py) deliberately do NOT gate on detected
language at all, for the same reason - see their docstrings.

Two model instances are lazily loaded independently, so an
English-only investigation (the common case) never pays the larger
multilingual model's load cost."""
from ..models import Severity, Signal

ENGLISH_MODEL_NAME = "all-MiniLM-L6-v2"
MULTILINGUAL_MODEL_NAME = "paraphrase-multilingual-MiniLM-L12-v2"
SITE_THRESHOLD = 0.24
TEXT_TRUNCATE_CHARS = 4000
LANG_DETECT_SAMPLE_CHARS = 500

SITE_CATEGORY_DESCRIPTIONS = {
    "phishing-clone": (
        "A fake login or account page impersonating a bank, email provider, "
        "or well-known online service, asking the visitor to sign in, verify "
        "their identity, or re-enter payment details."
    ),
    "scam-shop": (
        "An online shop or deal page with unrealistic discounts, urgency "
        "countdown timers, no verifiable contact information, and pressure "
        "to buy or pay immediately."
    ),
    "malware-risk": (
        "A page urging the visitor to download and run a file, install a "
        "browser extension or 'codec'/'player' update, or enable macros to "
        "view content."
    ),
    "legitimate": (
        "A normal, legitimate website - a real business, news outlet, "
        "government page, or informational site with no signs of "
        "impersonation, urgency, or fraud."
    ),
    "other": (
        "A page that doesn't clearly fit a phishing login page, a scam "
        "shop, or a malware-download page."
    ),
}

_category_names = list(SITE_CATEGORY_DESCRIPTIONS.keys())
_models: "dict[str, tuple]" = {}  # model_name -> (SentenceTransformer, category_embeddings)


def _get_model(model_name: str):
    if model_name not in _models:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer(model_name)
        embeddings = model.encode(list(SITE_CATEGORY_DESCRIPTIONS.values()), convert_to_tensor=True)
        _models[model_name] = (model, embeddings)
    return _models[model_name]


def _detect_is_english(text: str) -> bool:
    try:
        from langdetect import detect
        return detect(text[:LANG_DETECT_SAMPLE_CHARS]) == "en"
    except Exception:  # noqa: BLE001 - langdetect can raise on short/ambiguous text; default to English model
        return True


def classify(text: str) -> "Signal | None":
    text = (text or "").strip()
    if not text:
        return None

    from sentence_transformers import util

    is_english = _detect_is_english(text)
    model_name = ENGLISH_MODEL_NAME if is_english else MULTILINGUAL_MODEL_NAME
    model, category_embeddings = _get_model(model_name)

    embedding = model.encode(text[:TEXT_TRUNCATE_CHARS], convert_to_tensor=True)
    scores = util.cos_sim(embedding, category_embeddings)[0]
    best_idx = int(scores.argmax())
    confidence = float(scores[best_idx])
    category = _category_names[best_idx] if confidence >= SITE_THRESHOLD else "other"

    if category in ("legitimate", "other"):
        return Signal(
            source="classifier", code="classifier_benign", severity=Severity.INFO,
            message=f"Page content classified as '{category}' (confidence {confidence:.2f}).",
            evidence={"category": category, "confidence": round(confidence, 3), "model": model_name},
        )

    return Signal(
        source="classifier", code="classifier_risk_category", severity=Severity.HIGH,
        message=f"Page content resembles '{category}' (confidence {confidence:.2f}).",
        evidence={"category": category, "confidence": round(confidence, 3), "model": model_name},
    )

"""Fake small-fee urgency scam detection - two related patterns sharing
the same underlying shape (an official-sounding entity claims you owe
a small amount, with a payment link that actually harvests card
details), kept in one module rather than duplicated across two:

1. Parcel/customs-fee scams - among the most widespread phishing
   patterns worldwide, seen with Correios (Brazil, often with PIX),
   Colissimo/La Poste (France), Royal Mail/DPD/Evri (UK), Germany,
   India, the Gulf, and Southeast Asia - essentially identical
   structure, just localized language and courier brand.
2. Toll-road scams (E-ZPass/SunPass/TxTag) - a US-concentrated pattern
   run at very large scale by organized smishing groups.

Deliberately checks patterns for all supported languages unconditionally
rather than gating on detected language (see classifier.py's docstring
for why language detection is unreliable enough on short text that
gating on it here would risk missing a real match). Parcel-fee patterns
cover English, Portuguese, French, German, and Spanish; toll patterns
currently cover English and Spanish (Smishing Triad campaigns are
documented targeting US Spanish-speaking populations too) - easy to
extend either set with the same shape."""
import re

from ..models import Severity, Signal

# "Something is being held/blocked" + parcel/delivery language, per
# language. Deliberately excludes bare "package"/"colis"/"pacote" alone
# - that word appears constantly in legitimate e-commerce/shipping
# content, so the HELD/BLOCKED framing is the actual signal.
_PARCEL_HELD_PATTERNS = (
    # English
    r"parcel\s+(?:is\s+)?(?:held|stuck|blocked)",
    r"package\s+(?:is\s+)?(?:held|stuck|blocked)",
    r"held\s+(?:at\s+)?customs",
    r"delivery\s+(?:is\s+)?(?:pending|on\s+hold)",
    # Portuguese
    r"pacote\s+(?:esta|está)\s+retid[oa]",
    r"encomenda\s+retida",
    r"retid[oa]\s+na\s+alf[aâ]ndega",
    # French
    r"colis\s+(?:est\s+)?(?:bloqu[ée]|retenu)",
    r"bloqu[ée]\s+en\s+douane",
    # German - see clickfix.py's docstring note on why umlauts need a
    # 3-way (native/bare-vowel/ue-oe-transliteration) alternation.
    r"paket\s+(?:wird\s+)?(?:zur(?:u|ü|ue)ckgehalten|festgehalten)",
    r"sendung\s+(?:wird\s+)?zur(?:u|ü|ue)ckgehalten",
    # Spanish
    r"paquete\s+(?:esta|está)\s+retenido",
    r"retenido\s+en\s+aduanas?",
)

# A fee/tax/duty payment demand, per language.
_FEE_DEMAND_PATTERNS = (
    # English
    r"customs\s+(?:fee|duty|charge)",
    r"import\s+(?:fee|duty|tax)",
    r"(?:pay|release)\s+(?:the\s+|a\s+)?(?:fee|duty)\s+to\s+(?:release|receive)",
    r"redelivery\s+fee",
    # Portuguese
    r"taxa\s+(?:alf[aâ]ndeg[aá]ria|de\s+importa[cç][aã]o)",
    r"pagu?e\s+a\s+taxa",
    # French
    r"frais\s+de\s+douane",
    r"payer\s+les\s+frais",
    # German
    r"zollgeb(?:u|ü|ue)hr",
    r"geb(?:u|ü|ue)hr\s+bezahlen",
    # Spanish
    r"tarifa\s+aduaner[ao]",
    r"pagar\s+la\s+tarifa",
)

# Real postal services explicitly warn that they never send payment
# links via SMS/email (confirmed for Correios: legitimate messages only
# come from @correios.com.br, and all real fees route through their own
# app/website - never an external link). This applies as a general rule
# across the postal services this pattern targets.
_CARRIER_HINT = (
    "dhl", "fedex", "ups", "usps", "royal mail", "correios", "la poste",
    "colissimo", "deutsche post", "dpd", "evri", "india post", "auspost",
    "australia post",
)

# Toll-road scam patterns - "you owe an unpaid toll" framing, distinct
# enough from the parcel-held language above to warrant its own set,
# though the overall page-level severity logic mirrors it exactly.
_TOLL_LANGUAGE_PATTERNS = (
    # English
    r"unpaid\s+toll",
    r"outstanding\s+toll\s+(?:balance|amount)",
    r"toll\s+violation",
    r"toll\s+(?:invoice|bill)\s+(?:is\s+)?(?:overdue|unpaid)",
    r"pay\s+(?:your\s+)?toll\s+(?:by|before)",
    # Spanish
    r"peaje\s+(?:pendiente|no\s+pagado|impago)",
    r"factura\s+de\s+peaje\s+(?:pendiente|vencida)",
)

_TOLL_AUTHORITY_HINT = (
    "e-zpass", "ezpass", "sunpass", "txtag", "tx-tag", "fastrak", "toll roads",
)


def check_toll(page_text: "str | None") -> "Signal | None":
    text_l = (page_text or "").lower()
    if not text_l:
        return None

    toll_hits = [p for p in _TOLL_LANGUAGE_PATTERNS if re.search(p, text_l)]
    if not toll_hits:
        return None

    mentions_authority = any(a in text_l for a in _TOLL_AUTHORITY_HINT)

    return Signal(
        source="delivery_fee", code="toll_scam_pattern",
        severity=Severity.HIGH if mentions_authority else Severity.MEDIUM,
        message=(
            "This page claims an unpaid toll balance and demands payment - the "
            "pattern behind a large, ongoing wave of toll-payment smishing. "
            "Real toll authorities bill by mail or through their own "
            "app/website, never through a link in an unsolicited text message."
        ),
        evidence={"toll_patterns": toll_hits, "mentions_authority": mentions_authority},
    )


def check(page_text: "str | None") -> "Signal | None":
    text_l = (page_text or "").lower()
    if not text_l:
        return None

    held_hits = [p for p in _PARCEL_HELD_PATTERNS if re.search(p, text_l)]
    fee_hits = [p for p in _FEE_DEMAND_PATTERNS if re.search(p, text_l)]

    if not (held_hits or fee_hits):
        return None

    mentions_carrier = any(c in text_l for c in _CARRIER_HINT)

    if held_hits and fee_hits:
        return Signal(
            source="delivery_fee", code="fake_delivery_fee_scam", severity=Severity.HIGH,
            message=(
                "This page claims a parcel is being held and demands a customs/delivery "
                "fee to release it - a globally common scam pattern. Real postal and "
                "courier services never request payment through a link in an SMS or "
                "email; legitimate fees are only ever paid through the carrier's own "
                "app or website."
            ),
            evidence={"held_patterns": held_hits, "fee_patterns": fee_hits, "mentions_carrier": mentions_carrier},
        )

    # Only one half of the pattern matched - still worth surfacing, but
    # more weakly, since either phrase alone has some legitimate uses
    # (e.g. a real "your delivery is pending" notification with no fee).
    return Signal(
        source="delivery_fee", code="delivery_fee_language_present", severity=Severity.LOW,
        message="This page uses language associated with fake parcel/customs-fee scams, "
                "though not the full held-parcel-plus-fee-demand pattern.",
        evidence={"held_patterns": held_hits, "fee_patterns": fee_hits},
    )

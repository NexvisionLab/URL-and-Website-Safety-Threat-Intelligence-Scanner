"""What the buyer tells us about the offer, which the website alone can't
show: how the seller asked to be paid, where the shop was advertised,
and the price.

How the seller asked to be paid is the single most telling fact in a
Singapore e-commerce scam - SPF reports victims were mostly told to pay
by PayNow or bank transfer - so it is weighed as evidence. Where the
advert ran is context only."""
from ..models import Severity, Signal

SOURCE = "shop_claims"

PAYMENT_CHOICES = {
    "card": "credit or debit card",
    "paypal": "PayPal",
    "platform": "the marketplace's own checkout",
    "paynow": "PayNow",
    "bank_transfer": "bank transfer",
    "crypto": "cryptocurrency",
    "gift_card": "gift cards",
    "other": "another method",
}
ADVERT_CHOICES = {
    "instagram": "Instagram", "facebook": "Facebook", "tiktok": "TikTok", "youtube": "YouTube",
    "google": "a Google search or ad", "telegram": "Telegram", "whatsapp": "WhatsApp",
    "email": "an email", "sms": "a text message", "other": "somewhere else",
}
DEEP_CLAIMED_DISCOUNT = 0.5


def clean(raw: "dict | None") -> dict:
    """Keeps only recognised values; anything else is dropped, not guessed at."""
    raw = raw or {}
    out = {}
    pay = str(raw.get("payment_requested") or "").strip().lower()
    if pay in PAYMENT_CHOICES:
        out["payment_requested"] = pay
    advert = str(raw.get("advertised_on") or "").strip().lower()
    if advert in ADVERT_CHOICES:
        out["advertised_on"] = advert
    for key in ("price_seen", "usual_price"):
        try:
            value = float(raw.get(key))
        except (TypeError, ValueError):
            continue
        if 0 < value < 10_000_000:
            out[key] = value
    return out


def signals(claims: dict) -> "list[Signal]":
    out = []
    pay = claims.get("payment_requested")
    if pay in ("crypto", "gift_card"):
        out.append(Signal(
            source=SOURCE, code="claim_payment_irreversible", severity=Severity.HIGH,
            message=(f"You were asked to pay with {PAYMENT_CHOICES[pay]}. Genuine shops don't ask for this, "
                     "and the money can't be recovered once sent."),
            evidence={"payment_requested": pay},
        ))
    elif pay in ("paynow", "bank_transfer"):
        out.append(Signal(
            source=SOURCE, code="claim_payment_transfer", severity=Severity.MEDIUM,
            message=(f"You were asked to pay by {PAYMENT_CHOICES[pay]}. A transfer can't be disputed like a card "
                     "payment, and it is how most e-commerce scam victims in Singapore were asked to pay (SPF, 2025)."),
            evidence={"payment_requested": pay},
        ))
    seen, usual = claims.get("price_seen"), claims.get("usual_price")
    if seen and usual and usual > seen and 1 - seen / usual >= DEEP_CLAIMED_DISCOUNT:
        pct = round((1 - seen / usual) * 100)
        out.append(Signal(
            source=SOURCE, code="claim_deep_discount", severity=Severity.MEDIUM,
            message=(f"The price you saw is {pct}% below the usual price you gave. "
                     "A price far below everyone else's is the most common lure of a fake shop."),
            evidence={"price_seen": seen, "usual_price": usual, "discount_pct": pct},
        ))
    advert = claims.get("advertised_on")
    if advert:
        out.append(Signal(
            source=SOURCE, code="claim_advertised_on", severity=Severity.INFO,
            message=f"You found this shop through {ADVERT_CHOICES[advert]}.",
            evidence={"advertised_on": advert},
        ))
    return out

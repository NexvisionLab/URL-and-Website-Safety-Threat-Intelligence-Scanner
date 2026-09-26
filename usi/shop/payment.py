"""How the shop says it takes payment.

What matters to a buyer is whether a payment can be taken back. A card
charge or a PayPal purchase can be disputed; a bank transfer, PayNow,
crypto or gift cards cannot. Watchlist Internet's experts and the FTC
both name "prepayment by transfer only" as a hallmark of fake shops, and
SPF reports that Singapore's e-commerce scam victims were mostly told
to pay by PayNow or bank transfer.

The analyzer can't open the checkout (it never adds to a cart or
submits anything), so this reads what the shop shows before checkout:
payment icons (their alt text, titles and class names are in the HTML),
FAQ and terms wording. An empty result is therefore not a finding."""
import re

from ..models import Severity, Signal

SOURCE = "shop_money"

REVERSIBLE = {
    "card": r"\bvisa\b|master\s?card|\bamex\b|american express|credit card|debit card|\bunionpay\b|\bmaestro\b|\bdiners club\b",
    "PayPal": r"\bpaypal\b",
    "Apple Pay": r"apple[\s-]?pay",
    "Google Pay": r"google[\s-]?pay|\bgpay\b",
    "Shop Pay": r"shop[\s-]?pay\b",
    "buy now, pay later": r"\bklarna\b|\batome\b|\bafterpay\b|\bclearpay\b|\bhoolah\b|\bzip ?pay\b",
}
TRANSFER = {
    "bank transfer": r"bank ?transfer|wire transfer|direct (?:bank )?transfer|bank deposit|\bvorkasse\b|[üu]berweisung|virement bancaire|transferencia bancaria|bonifico",
    "PayNow": r"\bpaynow\b|\bpaylah\b",
}
IRREVERSIBLE = {
    "cryptocurrency": r"\bbitcoin\b|\bbtc\b|\busdt\b|\btether\b|\bethereum\b|cryptocurrenc(?:y|ies)|pay (?:with|in|by) crypto",
    "gift cards": r"pay (?:by|with|using) (?:a |an )?(?:[a-z]+ )?gift ?cards?|gift ?cards? (?:as|for) payment",
    "money transfer services": r"western union|moneygram",
}


def _find(groups: "dict[str, str]", haystack: str) -> "list[str]":
    return [name for name, rx in groups.items() if re.search(rx, haystack)]


def detect(html_pages: "list[str]", text_pages: "list[str]") -> dict:
    """Card and wallet logos are usually images or icons, so their names are read from the HTML
    (alt text, titles, class names). Transfers and crypto are read from the visible text only:
    page scripts are full of words like "btc" and "transfer" that say nothing about payment."""
    text = " ".join(t.lower() for t in text_pages)
    html = " ".join(h.lower() for h in html_pages) + " " + text
    return {
        "reversible": _find(REVERSIBLE, html),
        "transfer": _find(TRANSFER, text),
        "irreversible": _find(IRREVERSIBLE, text),
    }


def signals(found: dict) -> "list[Signal]":
    out = []
    if found["irreversible"]:
        methods = ", ".join(found["irreversible"])
        out.append(Signal(
            source=SOURCE, code="shop_payment_irreversible", severity=Severity.MEDIUM,
            message=(f"The shop mentions paying by {methods}. Money sent this way can't be recovered "
                     "if the goods never arrive."),
            evidence=found,
        ))
    if (found["transfer"] or found["irreversible"]) and not found["reversible"]:
        methods = ", ".join(found["transfer"] + found["irreversible"])
        out.append(Signal(
            source=SOURCE, code="shop_prepayment_only", severity=Severity.MEDIUM,
            message=(f"The only ways to pay we could see are {methods} - no card or PayPal. "
                     "Those payments can't be disputed, which is why fake shops prefer them."),
            evidence=found,
        ))
    if not out:
        seen = found["reversible"] + found["transfer"]
        out.append(Signal(
            source=SOURCE, code="shop_payment_methods", severity=Severity.INFO,
            message=("Payment methods shown: " + ", ".join(seen) + ".") if seen else
                    "No payment methods are shown before checkout, so we couldn't tell how this shop takes payment.",
            evidence=found,
        ))
    return out

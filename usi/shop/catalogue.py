"""Discount depth and catalogue age, measured rather than guessed.

Most shop builders publish the catalogue in a machine-readable form:
Shopify stores answer /products.json with each product's price, its
"compare at" (crossed-out) price and when it was created; WooCommerce
stores answer the Store API with regular and sale prices. From that the
analyzer can say "37 of 40 products are marked down, typically by 70%"
and "every product was first listed 12 days ago" - the pattern of the
mass-produced fake shops (one template, a scraped catalogue, a
catalogue-wide 'clearance') that a genuine shop rarely matches.

For other shops, only the "-70%" / "70% off" badges in the page are
counted, which is weaker and needs more of them before it says anything."""
import re
import statistics
from datetime import datetime, timezone
from urllib.parse import urljoin

from ..models import Severity, Signal

SOURCE = "shop_money"
AGE_SOURCE = "shop_age"

MIN_PRODUCTS = 8                 # fewer than this and a share says little
DEEP_DISCOUNT = 0.50             # "half price or less"
DISCOUNTED_SHARE = 0.60          # most of the catalogue is marked down...
MEDIAN_DEEP = 0.50               # ...and the typical markdown is half or more
# ...or practically every product is marked down. Measured 2026-09-25: two confirmed fake shops had 100%
# of their catalogue discounted (typically by 38-39%); among 14 genuine shops with a readable catalogue the
# highest share was 84% (typically 10% off), most were under 30%.
EVERYTHING_ON_SALE_SHARE = 0.95
EVERYTHING_ON_SALE_MIN_PRODUCTS = 20
EVERYTHING_ON_SALE_MEDIAN = 0.25
MIN_BADGES = 5
NEW_CATALOGUE_DAYS = 60
MIN_PRODUCTS_FOR_AGE = 10


def detect_platform(html: str) -> "str | None":
    h = (html or "").lower()
    if "cdn.shopify.com" in h or "shopify.theme" in h or "myshopify.com" in h:
        return "shopify"
    if "wp-content/plugins/woocommerce" in h or "woocommerce-page" in h or "wc-block" in h:
        return "woocommerce"
    return None


def feed_url(platform: str, base_url: str) -> "str | None":
    if platform == "shopify":
        return urljoin(base_url, "/products.json?limit=250")
    if platform == "woocommerce":
        return urljoin(base_url, "/wp-json/wc/store/v1/products?per_page=100")
    return None


def _num(value) -> "float | None":
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def _date(value) -> "datetime | None":
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_shopify(data) -> "list[dict]":
    """One entry per product: its lowest-priced variant's price and
    crossed-out price, and when the product was created."""
    items = []
    products = data.get("products") if isinstance(data, dict) else None
    for p in products or []:
        if not isinstance(p, dict):
            continue
        best = None
        for v in p.get("variants") or []:
            if not isinstance(v, dict):
                continue
            price = _num(v.get("price"))
            if price is None:
                continue
            if best is None or price < best[0]:
                best = (price, _num(v.get("compare_at_price")))
        if best is None:
            continue
        items.append({"price": best[0], "was": best[1],
                      "created": _date(p.get("created_at")) or _date(p.get("published_at"))})
    return items


def parse_woocommerce(data) -> "list[dict]":
    items = []
    for p in data if isinstance(data, list) else []:
        prices = p.get("prices") if isinstance(p, dict) else None
        if not isinstance(prices, dict):
            continue
        price, regular = _num(prices.get("price")), _num(prices.get("regular_price"))
        if price is None:
            continue
        items.append({"price": price, "was": regular, "created": None})
    return items


def summarise(items: "list[dict]", now: "datetime | None" = None) -> dict:
    now = now or datetime.now(timezone.utc)
    discounts = [1 - it["price"] / it["was"] for it in items if it["was"] and it["was"] > it["price"]]
    created = [it["created"] for it in items if it["created"]]
    facts = {
        "products_checked": len(items),
        "discounted": len(discounts),
        "discounted_share": round(len(discounts) / len(items), 3) if items else 0.0,
        "median_discount": round(statistics.median(discounts), 3) if discounts else 0.0,
        "deep_discounted": sum(1 for d in discounts if d >= DEEP_DISCOUNT),
    }
    if created:
        first = min(created)
        facts["first_listed"] = first.date().isoformat()
        facts["first_listed_days"] = max(0, (now - first).days)
    return facts


_BADGE_RE = re.compile(
    r"(?:(?<![\w.])-\s?(\d{2})\s?%(?!\w))"            # "-70%"
    r"|(?:\b(\d{2})\s?%\s?(?:off|rabatt|korting|de r[ée]duction|descuento)\b)"   # "70% off"
    r"|(?:\bsave\s(\d{2})\s?%)",                        # "save 70%"
    re.I,
)


def badge_discounts(text: str) -> "list[int]":
    out = []
    for m in _BADGE_RE.finditer(text or ""):
        value = int(next(g for g in m.groups() if g))
        if 5 <= value <= 95:
            out.append(value)
    return out


def signals_from_feed(facts: dict, platform: str, domain_age_days: "int | None" = None) -> "list[Signal]":
    """`domain_age_days` decides how much a new catalogue weighs: on a domain known to be older than a
    year it is most likely a shop that moved platform (LOW); where the registry doesn't publish an age
    (.de, .at and others) or the domain is itself under a year old, it is the best evidence of a new shop."""
    signals = []
    n = facts.get("products_checked", 0)
    pct = round(facts.get("median_discount", 0) * 100)
    if n >= MIN_PRODUCTS and facts["discounted_share"] >= DISCOUNTED_SHARE and facts["median_discount"] >= MEDIAN_DEEP:
        signals.append(Signal(
            source=SOURCE, code="shop_deep_discounts", severity=Severity.MEDIUM,
            message=(f"{facts['discounted']} of the {n} products we checked are marked down, typically by {pct}%. "
                     "Genuine shops rarely discount most of their range by half or more; fake shops do it to rush buyers."),
            evidence={**facts, "via": platform},
        ))
    elif (n >= EVERYTHING_ON_SALE_MIN_PRODUCTS and facts["discounted_share"] >= EVERYTHING_ON_SALE_SHARE
          and facts["median_discount"] >= EVERYTHING_ON_SALE_MEDIAN):
        signals.append(Signal(
            source=SOURCE, code="shop_deep_discounts", severity=Severity.MEDIUM,
            message=(f"{facts['discounted']} of the {n} products we checked are marked down, typically by {pct}% - "
                     "practically the whole shop is 'on sale'. Genuine shops rarely do this; fake shops use it to "
                     "make every price look like a bargain."),
            evidence={**facts, "via": platform, "pattern": "everything_on_sale"},
        ))
    days = facts.get("first_listed_days")
    if days is not None and n >= MIN_PRODUCTS_FOR_AGE and days < NEW_CATALOGUE_DAYS:
        established = domain_age_days is not None and domain_age_days >= 365
        signals.append(Signal(
            source=AGE_SOURCE, code="shop_catalogue_new", severity=Severity.LOW if established else Severity.MEDIUM,
            message=(f"The oldest product in this shop was first listed {days} day(s) ago, "
                     "so the shop itself appears to be very new."),
            evidence={"first_listed": facts.get("first_listed"), "first_listed_days": days,
                      "products_checked": n, "via": platform},
        ))
    if n and not signals:
        signals.append(Signal(
            source=SOURCE, code="shop_catalogue", severity=Severity.INFO,
            message=(f"Checked {n} products: {facts['discounted']} marked down"
                     + (f", typically by {round(facts['median_discount'] * 100)}%." if facts["discounted"] else ".")),
            evidence={**facts, "via": platform},
        ))
    return signals


def signals_from_badges(values: "list[int]") -> "list[Signal]":
    if len(values) < MIN_BADGES:
        return []
    median = statistics.median(values)
    if median < MEDIAN_DEEP * 100:
        return []
    return [Signal(
        source=SOURCE, code="shop_deep_discounts", severity=Severity.MEDIUM,
        message=(f"The page shows {len(values)} discount labels, typically {round(median)}% off. "
                 "Genuine shops rarely discount most of their range by half or more; fake shops do it to rush buyers."),
        evidence={"badges": values[:30], "median_badge": median, "via": "page"},
    )]

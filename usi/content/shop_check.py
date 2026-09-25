"""Fake online shop detection.

A fake shop copies a real shop's look, prices its goods far below market, and takes payment for goods that never
arrive. No single feature proves it: plenty of real shops have a countdown banner, and plenty of fake ones have a
tidy page. So this module reports each feature it can see as its own signal, and says "several classic fake-shop
signs together" only when independent kinds of red flag line up.

It reads the page's HTML and visible text, plus the WHOIS age signal already gathered. It never contacts the shop.

Guards against false alarms on real shops:
- Nothing is reported unless the page is recognisably a shop (a cart or checkout, prices, a shop platform).
- Things that are *missing* (contact details, policies) are only reported when the page has enough visible text to
  have shown them. A page built mostly by scripts is reported as "not fully readable" instead.
- The summary flags are counted by kind, so three signs of the same kind do not add up to a warning.
"""
import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from ..models import Severity, Signal

MIN_TEXT_FOR_ABSENCE_CHECKS = 400  # visible characters needed before "not found" means anything

# Brands whose goods are copied by fake shops, with the domains that genuinely sell them. A page in one of these
# brands' names on any other domain, at a deep discount, is a classic fake shop.
BRANDS = {
    "nike": ("nike.com",), "adidas": ("adidas.com",), "puma": ("puma.com",), "new balance": ("newbalance.com",),
    "converse": ("converse.com",), "vans": ("vans.com",), "ugg": ("ugg.com",), "the north face": ("thenorthface.com",),
    "canada goose": ("canadagoose.com",), "lululemon": ("lululemon.com",), "gymshark": ("gymshark.com",),
    "apple": ("apple.com",), "samsung": ("samsung.com",), "sony": ("sony.com", "sony.net"), "bose": ("bose.com",),
    "dyson": ("dyson.com",), "lego": ("lego.com",), "ray-ban": ("ray-ban.com",), "oakley": ("oakley.com",),
    "pandora": ("pandora.net",), "tiffany": ("tiffany.com",), "louis vuitton": ("louisvuitton.com",),
    "gucci": ("gucci.com",), "prada": ("prada.com",), "michael kors": ("michaelkors.com",), "coach": ("coach.com",),
    "hermes": ("hermes.com",), "ikea": ("ikea.com",), "zara": ("zara.com",), "h&m": ("hm.com",),
    "uniqlo": ("uniqlo.com",), "birkenstock": ("birkenstock.com",), "crocs": ("crocs.com",), "hoka": ("hoka.com",),
    "under armour": ("underarmour.com",), "levi's": ("levi.com",), "tommy hilfiger": ("tommy.com",),
    "calvin klein": ("calvinklein.com",), "nintendo": ("nintendo.com",), "playstation": ("playstation.com",),
    "garmin": ("garmin.com",), "fitbit": ("fitbit.com",), "gopro": ("gopro.com",), "yeti": ("yeti.com",),
}

CHEAP_TLDS = {"shop", "store", "top", "xyz", "online", "site", "cyou", "click", "vip", "buzz", "sale", "club", "life"}
BARGAIN_WORDS = ("outlet", "sale", "discount", "clearance", "deals", "cheap", "official", "factory", "warehouse", "bargain")

PLATFORMS = (
    ("Shopify", re.compile(r"cdn\.shopify\.com|Shopify\.theme|myshopify\.com", re.I)),
    ("WooCommerce", re.compile(r"woocommerce|wp-content/plugins/woocommerce", re.I)),
    ("Magento", re.compile(r"Magento|mage/cookies|/static/frontend/", re.I)),
    ("BigCommerce", re.compile(r"bigcommerce\.com|cdn11\.bigcommerce", re.I)),
    ("PrestaShop", re.compile(r"prestashop", re.I)),
    ("OpenCart", re.compile(r"opencart|catalog/view/theme", re.I)),
    ("Wix Stores", re.compile(r"wixstores|wix\.com/.*stores", re.I)),
)
CART_WORDS = re.compile(r"(?i)\b(add to (?:cart|bag|basket)|buy it now|buy now|shopping (?:cart|bag|basket)|checkout|view cart|in stock|add to wishlist)\b")
PRICE = re.compile(r"(?:[$£€]|S\$|US\$|A\$|C\$|RM|Rs\.?|USD|EUR|GBP|SGD)\s?\d[\d,]*(?:\.\d{2})?|\d[\d,]*(?:\.\d{2})?\s?(?:USD|EUR|GBP|SGD)")
PERCENT_OFF = re.compile(r"(?i)(?:save|up to|sale|extra|flat|-)?\s*(\d{2})\s?%\s*(?:off|discount|sale)\b|(?:-|−)\s?(\d{2})\s?%")
CLOSING = re.compile(r"(?i)\b(closing[- ]down|going out of business|liquidation|final clearance|store closing|shutting down|warehouse clearance|everything must go)\b")
COUNTDOWN = re.compile(r"(?i)\b(?:offer|sale|deal|promotion)\s+ends?\s+(?:in|today|soon|at midnight)\b|\bends in\s+\d|\bhurry\b|\blast chance\b|\bonly\s+\d+\s+(?:left|remaining|in stock)\b|\b\d+\s+(?:people|customers|shoppers)\s+(?:are\s+)?(?:viewing|watching|looking)\b|\blimited (?:time|stock)\b")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
PHONE = re.compile(r"(?<!\d)(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,4}\d{2,4}(?!\d)")
ADDRESS = re.compile(r"(?i)\b\d{1,5}\s+[A-Za-z0-9 .'-]{3,40}\s+(?:street|st\.?|road|rd\.?|avenue|ave\.?|lane|ln\.?|drive|dr\.?|boulevard|blvd|way|place|plaza|court|suite|unit|floor)\b|\b(?:P\.?O\.? box)\s+\d+")
FREE_MAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "proton.me", "protonmail.com", "icloud.com", "qq.com", "163.com", "aol.com", "live.com"}
CONTACT_LINK = re.compile(r"(?i)contact|customer[- ]?(?:service|care|support)|support|help[- ]?(?:center|centre)|about[- ]?us")
POLICY = {
    "returns": re.compile(r"(?i)return|refund|exchange"),
    "shipping": re.compile(r"(?i)shipping|delivery|dispatch"),
    "terms": re.compile(r"(?i)terms(?: (?:of|and|&) (?:service|use|conditions|sale))?|conditions of (?:use|sale)"),
    "privacy": re.compile(r"(?i)privacy"),
}
CARD_PAYMENT = re.compile(r"(?i)\b(visa|mastercard|master card|american express|amex|paypal|stripe|apple pay|google pay|shop pay|klarna|afterpay|adyen|worldpay|credit card|debit card)\b")
_RISKY_METHODS = r"(?:bank transfer|wire transfer|western union|moneygram|zelle|cash ?app|bitcoin|btc|usdt|ethereum|crypto(?:currency)?|gift ?cards?|paynow|venmo|direct deposit)"
# "E-Gift Card" in a footer is a product the shop sells, not a way to pay it. These count only when a sentence is about paying.
RISKY_PAYMENT = re.compile(
    r"(?i)\b(?:pay(?:ment)?s?|accept(?:ed|ing)?|checkout|settle|deposit)\b[^.!?\n]{0,80}?\b(" + _RISKY_METHODS + r")\b"
    r"|\b(" + _RISKY_METHODS + r")\b[^.!?\n]{0,25}\b(?:only|payments?|accepted)\b"
)
REGISTRATION = re.compile(r"(?i)\b(?:company|business)\s+(?:registration|reg\.?|number|no\.?)\b|\bUEN\b|\bVAT\s+(?:number|no\.?|id)\b|\bABN\b|\b(?:registered|company)\s+(?:in|number)\b|\bLtd\.?\b|\bPte\.? Ltd\b|\bGmbH\b|\bLLC\b|\bInc\.?\b")


def _sig(code, severity, message, **evidence):
    return Signal(source="shop", code=code, severity=severity, message=message, evidence=evidence)


def _is_shop(html_l: str, text: str) -> "tuple[bool, list[str], str]":
    reasons: "list[str]" = []
    platform = ""
    for name, pattern in PLATFORMS:
        if pattern.search(html_l):
            platform = name
            reasons.append(f"built on {name}")
            break
    if CART_WORDS.search(text):
        reasons.append("cart or checkout wording")
    if len(PRICE.findall(text)) >= 3:
        reasons.append("several prices")
    if '"@type":"product"' in html_l.replace(" ", "") or '"@type":"offer"' in html_l.replace(" ", ""):
        reasons.append("product markup")
    return len(reasons) >= 2, reasons, platform


def _price_value(text: str) -> "float | None":
    match = re.search(r"\d[\d,]*(?:\.\d{1,2})?", text)
    if not match:
        return None
    try:
        return float(match.group(0).replace(",", ""))
    except ValueError:
        return None


_BARE_PRICE = re.compile(r"^\W{0,6}(?:US|S|A|C)?\$?\W{0,3}(\d[\d,]*(?:\.\d{1,2})?)\W{0,4}(?:USD|EUR|GBP|SGD)?$")
MIN_STRUCK_ITEMS = 4  # a few crossed-out prices are normal; a whole catalogue at 70% off is not


def _bare_price(text: str) -> "float | None":
    match = _BARE_PRICE.match(text.strip())
    if not match:
        return None
    try:
        return float(match.group(1).replace(",", ""))
    except ValueError:
        return None


def _struck_price_discounts(soup: "BeautifulSoup") -> "list[float]":
    """Discount fractions from a crossed-out price sitting directly beside the current price (del, s or strike)."""
    found: "list[float]" = []
    for old in soup.find_all(["del", "s", "strike"])[:120]:
        old_value = _bare_price(old.get_text(" ", strip=True))
        if not old_value:
            continue
        candidates = [x for x in old.next_siblings][:3] + [x for x in old.previous_siblings][:2]
        for sibling in candidates:
            text = sibling.get_text(" ", strip=True) if hasattr(sibling, "get_text") else str(sibling)
            new_value = _bare_price(text)
            if new_value and 0 < new_value < old_value:
                found.append(1 - new_value / old_value)
                break
    return found


_HOST_FILLER = set(BARGAIN_WORDS) | {"shop", "store", "online", "shoes", "bags", "uk", "us", "au", "ca", "eu", "sg", "outlets", "deals", "mall", "world", "hub"}


def _names_brand(brand: str, title: "str | None", host: str) -> bool:
    """True if the brand is named in the page title (as a whole word) or in the host as the brand itself, or the brand
    plus only bargain or shop filler words ("nike-outlet", "nikeshoesale"). "pineapple" does not name Apple."""
    if title and re.search(rf"(?<![a-z0-9]){re.escape(brand)}(?![a-z0-9])", title.lower()):
        return True
    token = brand.replace(" ", "").replace("'", "")
    label = host.lower().rsplit(".", 1)[0].split(".")[-1]
    for part in re.split(r"[-_]", label):
        if part == token:
            return True
        if part.startswith(token):
            rest = part[len(token):]
            if rest.isdigit() or rest in _HOST_FILLER or (len(rest) > 3 and any(rest.startswith(w) or rest.endswith(w) for w in _HOST_FILLER)):
                return True
    return False


def _official(host: str, domains: "tuple[str, ...]") -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in domains)


def check(host: str, title: "str | None", text: str, raw_html: str, prior_signals: "list[Signal] | None" = None) -> "list[Signal]":
    """Returns the shop signals for a fetched page, or an empty list if the page is not a shop."""
    text = text or ""
    html_l = (raw_html or "").lower()
    is_shop, reasons, platform = _is_shop(html_l, text)
    if not is_shop:
        return []

    signals = [_sig("shop_detected", Severity.INFO, "This looks like an online shop (" + ", ".join(reasons) + ").", reasons=reasons, platform=platform)]
    readable = len(text) >= MIN_TEXT_FOR_ABSENCE_CHECKS
    if not readable:
        signals.append(_sig("shop_page_not_fully_readable", Severity.INFO,
                            "Most of this page is built by scripts, so contact details and policies could not be looked for.", text_chars=len(text)))

    soup = BeautifulSoup(raw_html or "", "lxml")
    flags: "dict[str, str]" = {}  # kind of red flag -> one-line reason
    good: "list[str]" = []

    # --- discounts
    discounts = [int(m.group(1) or m.group(2)) for m in PERCENT_OFF.finditer(text)]
    discounts = [d for d in discounts if 10 <= d <= 99]
    top_claim = max(discounts) if discounts else 0
    struck = [d for d in _struck_price_discounts(soup) if d >= 0.7]
    if top_claim >= 70 or len(struck) >= MIN_STRUCK_ITEMS:
        detail = f"claims of up to {top_claim}% off" if top_claim >= 70 else f"{len(struck)} items priced at 70% or more below their crossed-out price"
        signals.append(_sig("shop_extreme_discount", Severity.MEDIUM,
                            f"Prices are cut far below normal: {detail}. Genuine shops rarely discount this deeply, and fake ones lead with it.",
                            claimed_percent=top_claim, deeply_discounted_items=len(struck)))
        flags["discount"] = detail
    closing = CLOSING.search(text)
    if closing:
        signals.append(_sig("shop_closing_down_sale", Severity.LOW, f"Uses a closing-down or clearance claim (“{closing.group(0)}”), a common cover story for deep discounts.", phrase=closing.group(0)))
        flags.setdefault("discount", closing.group(0))

    # --- pressure
    pressure = COUNTDOWN.search(text) or ('data-countdown' in html_l) or ('class="countdown' in html_l) or ("countdown" in html_l and "timer" in html_l)
    if pressure:
        phrase = pressure.group(0) if hasattr(pressure, "group") else "a countdown timer"
        signals.append(_sig("shop_pressure_tactics", Severity.LOW, f"Uses urgency to hurry the buyer (“{phrase}”). Many real shops do too, so this only counts alongside other signs.", phrase=phrase))
        flags["pressure"] = phrase

    # --- contact details
    if readable:
        emails = EMAIL.findall(text) + [m.group(1) for m in EMAIL.finditer(html_l) if "mailto:" in html_l[max(0, m.start() - 8):m.start()]]
        has_email = bool(emails)
        # Prices and decimals ("199.99 249.99") look like phone numbers, so take them out first.
        digits_text = re.sub(r"\d[\d,]*\.\d{1,2}", " ", PRICE.sub(" ", text))
        has_phone = any(len(re.sub(r"\D", "", m.group(0))) >= 8 for m in PHONE.finditer(digits_text))
        has_address = bool(ADDRESS.search(text))
        contact_links = [a for a in soup.find_all("a", href=True) if CONTACT_LINK.search(a.get_text(" ", strip=True) + " " + a["href"])]
        if not (has_email or has_phone or has_address):
            severity = Severity.MEDIUM
            message = "No email address, phone number or street address was found on the page."
            if contact_links:
                severity, message = Severity.LOW, "No email, phone or address is on this page, only a link to a contact page. Check that page yourself."
            signals.append(_sig("shop_no_contact_details", severity, message, contact_page_linked=bool(contact_links)))
            if severity == Severity.MEDIUM:
                flags["no_contact"] = "no contact details"
        else:
            good.append("contact details are shown")
            if has_email and all(domain.lower() in FREE_MAIL for domain in emails) and not (has_phone or has_address):
                signals.append(_sig("shop_free_mail_contact", Severity.LOW, "The only contact is a free personal email address (" + emails[0] + "), not one at the shop's own domain.", email=emails[0]))
                flags["free_mail"] = "free-mail contact only"
            if has_address:
                good.append("a street address is given")

    # --- policies
    if readable:
        link_text = " ".join(a.get_text(" ", strip=True) + " " + a["href"] for a in soup.find_all("a", href=True))
        found_policies = [name for name, pattern in POLICY.items() if pattern.search(link_text)]
        if len(found_policies) == 0:
            signals.append(_sig("shop_no_policies", Severity.MEDIUM, "There is no link to returns, shipping, terms or privacy pages. Real shops are required to publish these."))
            flags["no_policies"] = "no returns, shipping, terms or privacy pages"
        elif "returns" not in found_policies:
            signals.append(_sig("shop_no_returns_policy", Severity.LOW, "There is no link to a returns or refund policy.", found=found_policies))
        else:
            good.append("a returns policy is linked")
        if REGISTRATION.search(text):
            good.append("a company name or registration is mentioned")

    # --- payment
    risky = [a or b for a, b in RISKY_PAYMENT.findall(text)]
    card = CARD_PAYMENT.findall(text)
    if risky and not card:
        signals.append(_sig("shop_untraceable_payment", Severity.HIGH,
                            "The only payment methods named are ones that cannot be reversed (" + ", ".join(sorted({r.lower() for r in risky})[:3]) + "), and no card or PayPal option is shown.",
                            methods=sorted({r.lower() for r in risky})))
        flags["payment"] = "only irreversible payment methods"
    elif card:
        good.append("card or PayPal payment is offered")

    # --- brand at a discount, on a domain that does not belong to the brand
    for brand, domains in BRANDS.items():
        if _names_brand(brand, title, host) and not _official(host, domains):
            if top_claim >= 50 or len(struck) >= MIN_STRUCK_ITEMS:
                signals.append(_sig("shop_brand_discount_unofficial", Severity.HIGH,
                                    f"Sells {brand.title()} goods at deep discounts on {host}, which is not {domains[0]}.", brand=brand, official=domains[0]))
                flags["brand"] = f"{brand.title()} goods on an unofficial domain"
            break

    # --- the domain itself
    tld = host.rsplit(".", 1)[-1].lower()
    label = host.rsplit(".", 2)[-2] if host.count(".") >= 1 else host
    if tld in CHEAP_TLDS and any(w in label.lower() for w in BARGAIN_WORDS):
        signals.append(_sig("shop_bargain_domain_name", Severity.LOW, f"The address ({host}) pairs a bargain word with a cheap domain ending (.{tld}), a common look for fake outlets.", host=host))
        flags["domain_name"] = host
    for prior in prior_signals or []:
        if prior.code == "young_domain":
            age = prior.evidence.get("age_days")
            signals.append(_sig("shop_new_domain", Severity.LOW, f"The shop's domain was registered only {age} day(s) ago. Fake shops are usually brand new.", age_days=age))
            flags["new_domain"] = f"registered {age} days ago"
            break

    if good:
        signals.append(_sig("shop_reassuring_signs", Severity.INFO, "Signs that count in the shop's favour: " + "; ".join(good) + ". Fake shops can copy these, so they are not proof.", signs=good))

    kinds = len(flags)
    if kinds >= 5 or (kinds >= 4 and ("payment" in flags or "brand" in flags)):
        signals.append(_sig("fake_shop_pattern", Severity.CRITICAL,
                            f"{kinds} different classic fake-shop signs appear together: " + "; ".join(flags.values()) + ". Do not pay this shop.",
                            red_flags=list(flags), count=kinds))
    elif kinds >= 3:
        signals.append(_sig("fake_shop_pattern", Severity.HIGH,
                            f"{kinds} different classic fake-shop signs appear together: " + "; ".join(flags.values()) + ".",
                            red_flags=list(flags), count=kinds))
    return signals

"""Shop risk bands: explicit, named rules - never a summed score.

Every rule that fires is returned with a plain-language reason, so the
report shows exactly why a shop landed in its band. The band is the
highest one any rule reaches:

  High                    - a strong sign on its own (a registration
                            number that doesn't exist, an irreversible
                            payment asked for), or a newness sign
                            together with a money or copying sign - the
                            combination mass-produced fake shops show.
  Elevated                - one clear warning sign, or several minor ones.
  Low                     - no warning sign found.
  Not enough information  - the shop's page couldn't be examined and no
                            rule fired on what could be checked.

The rules read the shop analyzer's own signals by code, plus the URL
investigation's verdict-level severities (a phishing-grade finding still
counts). Rule ids are stable so results can be compared over time."""
from ..models import Severity, Signal

HIGH, ELEVATED, LOW, NOT_ENOUGH = "High", "Elevated", "Low", "Not enough information"
_ORDER = {NOT_ENOUGH: 0, LOW: 1, ELEVATED: 2, HIGH: 3}

NEW = {"shop_domain_new", "shop_catalogue_new", "shop_uen_recent", "shop_cert_new"}
MONEY = {"shop_prepayment_only", "shop_payment_irreversible", "claim_payment_transfer", "claim_payment_irreversible"}
DISCOUNT = {"shop_deep_discounts", "claim_deep_discount"}
COPY = {"shop_brand_in_address", "shop_official_claim"}
BAD_REGISTRATION = {"shop_uen_deregistered"}
# Signs that need only the web address - what's left to judge when the page is blocked.
ADDRESS_MINOR = {"shop_domain_recent", "shop_random_name", "shop_old_domain_new_site"}
# The URL investigation's own young-domain signal duplicates shop_domain_new.
_URL_DUPLICATES = {"young_domain"}
# The URL engine's embedding classifier can't tell genuine shops from scam pages (its own notes: paypal.com
# scores as "scam-shop" as high as synthetic scam text), and measured on genuine shops it raised a HIGH
# "malware-risk" on a German coffee retailer. Shop verdicts don't rest on it.
_URL_IGNORED_SOURCES = {"classifier"}


def _codes(signals: "list[Signal]", severity: Severity = Severity.LOW) -> "set[str]":
    return {s.code for s in signals if s.severity >= severity}


def rate(url_signals: "list[Signal]", shop_signals: "list[Signal]", page_examined: bool) -> "tuple[str, list[dict]]":
    fired: "list[dict]" = []

    def fire(rule_id: str, band: str, reason: str):
        fired.append({"id": rule_id, "band": band, "reason": reason})

    codes = _codes(shop_signals)
    url_real = [s for s in url_signals if s.code not in _URL_DUPLICATES and s.source not in _URL_IGNORED_SOURCES
                and not s.source.startswith("shop")]
    url_critical = [s for s in url_real if s.severity == Severity.CRITICAL]
    url_high = [s for s in url_real if s.severity == Severity.HIGH]
    lookalike = [s for s in url_high if s.source in ("typosquat", "brand_impersonation", "favicon")]

    new, money, discount = codes & NEW, codes & MONEY, codes & DISCOUNT
    copy = (codes & COPY) | ({"url_lookalike"} if lookalike else set())

    if url_critical:
        fire("url_critical", HIGH, "The website check found a serious threat: " + url_critical[0].message)
    uen_not_found_high = [s for s in shop_signals if s.code == "shop_uen_not_found" and s.severity >= Severity.HIGH]
    if uen_not_found_high or codes & BAD_REGISTRATION:
        fire("registration_invalid", HIGH,
             "The business registration number on the site doesn't belong to a currently registered business.")
    if "shop_cloaked_for_ads" in codes:
        fire("cloaked_for_ads", HIGH,
             "The shop hides its storefront from everyone except phone visitors arriving from Facebook ads.")
    if "claim_payment_irreversible" in codes:
        fire("irreversible_payment_requested", HIGH, "You were asked to pay by crypto or gift cards.")
    if new and money:
        fire("new_shop_unprotected_payment", HIGH,
             "A newly created shop that takes only payments that can't be disputed.")
    if new and discount:
        fire("new_shop_deep_discounts", HIGH, "A newly created shop with most of its range marked down by half or more.")
    if copy and (new or discount):
        fire("brand_copy_new_or_discounted", HIGH,
             "The shop borrows a known brand's name and is either newly created or selling at deep discounts.")
    if "shop_template_text" in codes and new:
        fire("template_new_shop", HIGH, "A newly created shop whose pages still contain template placeholder text.")
    if "shop_known_fake_hosting" in codes and (new or "shop_random_name" in codes):
        fire("known_fake_hosting_new_shop", HIGH,
             "A new shop on a server that security researchers reported as hosting a network of fake shops.")
    if "shop_network_high_risk" in codes and (new or money or discount):
        fire("network_with_high_risk_shops", HIGH,
             "A new or suspicious shop that shares accounts or contact details with shops already rated High risk.")
    if "shop_random_name" in codes and new:
        fire("random_name_new_shop", HIGH, "A newly created shop with a name made of random letters.")

    medium_shop = sorted(_codes(shop_signals, Severity.MEDIUM))
    if len(medium_shop) >= 3:
        fire("several_warning_signs", HIGH, f"{len(medium_shop)} separate warning signs were found.")
    if url_high:
        fire("url_high", ELEVATED, "The website check raised a warning: " + url_high[0].message)
    if medium_shop:
        fire("warning_sign", ELEVATED, "At least one clear warning sign was found.")
    low_only = sorted(_codes(shop_signals, Severity.LOW) - set(medium_shop))
    if len(low_only) >= 3:
        fire("several_minor_signs", ELEVATED, f"{len(low_only)} minor warning signs were found together.")
    address_minor = sorted(codes & ADDRESS_MINOR)
    if not page_examined and len(address_minor) >= 2:
        fire("blocked_page_address_signs", ELEVATED,
             "We couldn't see the shop's page, and its web address shows more than one warning sign.")

    if fired:
        band = max((r["band"] for r in fired), key=_ORDER.get)
    else:
        band = LOW if page_examined else NOT_ENOUGH
    return band, fired

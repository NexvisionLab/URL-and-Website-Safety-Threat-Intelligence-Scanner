"""Shops that borrow a known retailer's name.

Fake shops often pose as a brand's outlet or clearance store
("currentbodyaustria.com", "eu-segway.com", "dyson-sale.shop") or call
themselves an "official store". The URL checker's lookalike rules are
tuned for phishing (logins, banks); this list and these rules are for
retail, and only the shop analyzer uses them.

A brand name counts as used in the web address when the address contains
it as a word ("nike-outlet"), starts or ends with it next to a shopping
or place word ("nikeoutlet", "dysonsingapore"), or - for longer, more
distinctive names - contains it anywhere ("currentbodyaustria")."""
import json
import re
from pathlib import Path

import tldextract

from ..models import Severity, Signal

SOURCE = "shop_copy"
DEFAULT_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "retail_brands.json"
DISTINCTIVE_LENGTH = 7

_extract = tldextract.TLDExtract(suffix_list_urls=())

AFFIXES = {
    "shop", "store", "outlet", "outlets", "sale", "sales", "official", "online", "mall", "deal", "deals",
    "discount", "clearance", "factory", "warehouse", "direct", "market", "boutique", "club", "world", "hub",
    "sg", "singapore", "asia", "eu", "europe", "uk", "us", "usa", "au", "de", "at", "austria", "ch", "fr",
    "it", "es", "nl", "my", "malaysia", "global", "intl", "international", "vip", "promo", "offer", "offers",
}


def load(path: "Path | None" = None) -> "list[dict]":
    with open(path or DEFAULT_PATH, encoding="utf-8") as f:
        return json.load(f)["brands"]


def _is_brand_host(host: str, brand: dict) -> bool:
    return any(host == d or host.endswith("." + d) for d in brand["domains"])


def _label_uses_key(label: str, key: str) -> bool:
    key = key.replace("-", "")
    tokens = [t for t in re.split(r"[-.]", label) if t]
    if key in tokens:
        return True
    flat = label.replace("-", "")
    if len(key) >= DISTINCTIVE_LENGTH and key in flat:
        return True
    for token in tokens:
        if token.startswith(key) and token[len(key):] in AFFIXES:
            return True
        if token.endswith(key) and token[:-len(key)] in AFFIXES:
            return True
    return False


def brand_in_address(host: str, brands: "list[dict]") -> "dict | None":
    host = host.lower().rstrip(".")
    if any(_is_brand_host(host, b) for b in brands):
        return None
    ext = _extract(host)
    label = ".".join(x for x in (ext.subdomain, ext.domain) if x and x != "www")
    best = None
    for brand in brands:
        for key in brand["keys"]:
            if _label_uses_key(label, key.lower()) and (best is None or len(key) > len(best[1])):
                best = (brand, key)
    return best[0] if best else None


def official_claim(host: str, title: str, text: str, brands: "list[dict]") -> "dict | None":
    """A page calling itself an official or authorised store of a brand
    whose website it isn't."""
    host = host.lower()
    haystack = f"{title or ''} {(text or '')[:20000]}".lower()
    for brand in brands:
        if _is_brand_host(host, brand):
            continue
        name = re.escape(brand["name"].lower())
        if re.search(rf"\bofficial\s+{name}\b|\b{name}\s+(?:official|authori[sz]ed)\s+(?:store|shop|outlet|website|site|online store)\b"
                     rf"|\bofficial\s+(?:store|shop|outlet|website|site)\s+(?:of|for)\s+{name}\b", haystack):
            return brand
    return None


def signals(host: str, title: str, text: str, brands: "list[dict]") -> "list[Signal]":
    brand = brand_in_address(host, brands)
    if brand:
        return [Signal(
            source=SOURCE, code="shop_brand_in_address", severity=Severity.MEDIUM,
            message=(f"The web address uses the name {brand['name']}, but this isn't {brand['name']}'s own website. "
                     f"{brand['name']}'s website is {brand['domains'][0]}."),
            evidence={"brand": brand["name"], "real_domains": brand["domains"][:3]},
        )]
    brand = official_claim(host, title, text, brands)
    if brand:
        return [Signal(
            source=SOURCE, code="shop_official_claim", severity=Severity.MEDIUM,
            message=(f"The page calls itself an official {brand['name']} store, but it isn't on "
                     f"{brand['name']}'s website ({brand['domains'][0]})."),
            evidence={"brand": brand["name"], "real_domains": brand["domains"][:3]},
        )]
    return []

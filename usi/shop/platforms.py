"""Recognises links to marketplaces, social networks and chat apps.

Most e-commerce scams reported in Singapore happen on real platforms,
not on fake websites: in 2025 Carousell and Facebook Marketplace
accounted for 29.0% and 22.2% of cases, and victims were told to pay a
deposit by PayNow or bank transfer (SPF Annual Scam and Cybercrime Brief
2025). For such a link the website itself is genuine - judging it would
only say "safe" and mislead. What the visitor needs is how safe that
platform is to transact on, and how to deal with the seller.

Ratings are MHA's E-commerce Marketplace Transaction Safety Ratings, as
published at RATINGS_URL on 2026-09-25 (4 ticks = all safety features
implemented). A platform MHA does not rate carries no rating here."""
from urllib.parse import urlparse

RATINGS_URL = "https://www.mha.gov.sg/e-commerce-marketplace-transaction-safety-ratings/"
RATINGS_CHECKED = "2026-09-25"

_PAY_IN_APP = (
    "Pay only through the platform's own checkout. Never transfer money to the seller directly, "
    "and don't move the conversation to WhatsApp or Telegram."
)
_CHECK_SELLER = "Check the seller's ratings, reviews and how long they have been selling."
_PRICE = "If the price is far below what other sellers ask, treat that as the main warning sign."
_DEPOSIT = ("Never pay a deposit or 'reservation fee' by PayNow or bank transfer. In 2025 most e-commerce "
            "scam victims in Singapore were asked to pay exactly this way (SPF).")
_MEET = "Where you can, meet in a public place and pay only once you have the item in hand."

# kind: "marketplace" (a platform with its own checkout), "classifieds"
# (listings between individuals), "social", "chat".
PLATFORMS = [
    {"id": "shopee", "name": "Shopee", "kind": "marketplace", "mha_ticks": 4, "rated_host": "shopee.sg",
     "domains": ["shopee.sg", "shopee.com.my", "shopee.co.id", "shopee.ph", "shopee.vn", "shopee.co.th",
                 "shopee.tw", "shopee.com.br", "shp.ee"],
     "advice": [_PAY_IN_APP, _CHECK_SELLER, _PRICE]},
    {"id": "lazada", "name": "Lazada", "kind": "marketplace", "mha_ticks": 4, "rated_host": "lazada.sg",
     "domains": ["lazada.sg", "lazada.com.my", "lazada.co.id", "lazada.com.ph", "lazada.vn", "lazada.co.th"],
     "advice": [_PAY_IN_APP, _CHECK_SELLER, _PRICE]},
    {"id": "amazon", "name": "Amazon", "kind": "marketplace", "mha_ticks": 4, "rated_host": "amazon.sg",
     "domains": ["amazon.sg", "amazon.com", "amazon.co.uk", "amazon.de", "amazon.com.au", "amazon.co.jp",
                 "amazon.in", "amzn.to", "amzn.asia"],
     "advice": [_PAY_IN_APP, _CHECK_SELLER, _PRICE]},
    {"id": "tiktok_shop", "name": "TikTok Shop", "kind": "marketplace", "mha_ticks": 4,
     "domains": ["shop.tiktok.com", "seller.tiktok.com"],
     "advice": [_PAY_IN_APP, _CHECK_SELLER, _PRICE]},
    {"id": "carousell", "name": "Carousell", "kind": "classifieds", "mha_ticks": 2,
     "domains": ["carousell.sg", "carousell.com", "carousell.com.my", "carousell.ph", "carousell.com.hk",
                 "carousell.tw", "carousell.co.id", "carousell.app.link"],
     "advice": [
         "Prefer sellers with the blue-tick Singpass-verified badge, and read their reviews.",
         "Use Carousell's own 'Buy' button, which pays through the platform, or meet in person.",
         _DEPOSIT, _MEET]},
    {"id": "facebook_marketplace", "name": "Facebook Marketplace", "kind": "classifieds", "mha_ticks": 1,
     "domains": ["facebook.com", "m.facebook.com", "web.facebook.com", "fb.com"], "path_prefix": "/marketplace",
     "advice": [
         "Facebook Marketplace has the fewest safety features of the platforms MHA rates.",
         _DEPOSIT, _MEET,
         "Check the seller's profile: a new account, few friends or no history is a warning sign."]},
    {"id": "qoo10", "name": "Qoo10", "kind": "marketplace", "mha_ticks": None,
     "domains": ["qoo10.sg", "qoo10.com"],
     "advice": [_PAY_IN_APP, _CHECK_SELLER, _PRICE]},
    {"id": "aliexpress", "name": "AliExpress", "kind": "marketplace", "mha_ticks": None,
     "domains": ["aliexpress.com", "aliexpress.us", "a.aliexpress.com"],
     "advice": [_PAY_IN_APP, _CHECK_SELLER, _PRICE]},
    {"id": "temu", "name": "Temu", "kind": "marketplace", "mha_ticks": None, "domains": ["temu.com"],
     "advice": [_PAY_IN_APP, _PRICE]},
    {"id": "shein", "name": "SHEIN", "kind": "marketplace", "mha_ticks": None, "domains": ["shein.com", "sg.shein.com"],
     "advice": [_PAY_IN_APP, _PRICE]},
    {"id": "ebay", "name": "eBay", "kind": "marketplace", "mha_ticks": None,
     "domains": ["ebay.com", "ebay.com.sg", "ebay.co.uk", "ebay.de", "ebay.com.au", "ebay.us"],
     "advice": [_PAY_IN_APP, _CHECK_SELLER, _PRICE]},
    {"id": "facebook", "name": "Facebook", "kind": "social", "mha_ticks": None,
     "domains": ["facebook.com", "m.facebook.com", "web.facebook.com", "fb.com", "fb.me", "fb.watch"]},
    {"id": "instagram", "name": "Instagram", "kind": "social", "mha_ticks": None,
     "domains": ["instagram.com", "instagr.am"]},
    {"id": "tiktok", "name": "TikTok", "kind": "social", "mha_ticks": None,
     "domains": ["tiktok.com", "vt.tiktok.com", "vm.tiktok.com"]},
    {"id": "xiaohongshu", "name": "Xiaohongshu (RED)", "kind": "social", "mha_ticks": None,
     "domains": ["xiaohongshu.com", "xhslink.com"]},
    {"id": "telegram", "name": "Telegram", "kind": "chat", "mha_ticks": None, "domains": ["t.me", "telegram.me"]},
    {"id": "whatsapp", "name": "WhatsApp", "kind": "chat", "mha_ticks": None,
     "domains": ["wa.me", "api.whatsapp.com", "chat.whatsapp.com", "whatsapp.com"]},
]

_SOCIAL_ADVICE = [
    "A seller on social media has no platform checkout and no buyer protection behind them.",
    "Ask for the business's registered name and UEN, and look it up on ACRA's BizFile (bizfile.gov.sg).",
    "Pay by credit card or PayPal Goods and Services, which let you dispute the charge, never by PayNow "
    "or bank transfer to a personal account.",
    _PRICE,
]
_CHAT_ADVICE = [
    "Buying through a chat app gives you no buyer protection at all, and scammers move buyers there on purpose.",
    _DEPOSIT,
    "If the seller also has a listing on a marketplace, go back and buy through the marketplace's checkout.",
]


def _host_matches(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def identify(url: str) -> "dict | None":
    """The platform a URL belongs to, or None for an independent website."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "").lower().rstrip(".")
    path = (parsed.path or "/").lower()
    if not host:
        return None
    for p in PLATFORMS:
        if not any(_host_matches(host, d) for d in p["domains"]):
            continue
        prefix = p.get("path_prefix")
        if prefix and not path.startswith(prefix):
            continue
        # TikTok Shop product links live on tiktok.com under /view/product or /shop.
        if p["id"] == "tiktok" and ("/view/product" in path or path.startswith("/shop")):
            p = next(x for x in PLATFORMS if x["id"] == "tiktok_shop")
        return _describe(p, host)
    return None


def _describe(p: dict, host: str) -> dict:
    ticks = p.get("mha_ticks")
    rated_host = p.get("rated_host")
    # MHA rates a platform's Singapore service; a foreign storefront of the
    # same company isn't what was rated.
    if ticks is not None and rated_host and not _host_matches(host, rated_host):
        ticks = None
    if p["kind"] == "social":
        advice = _SOCIAL_ADVICE
    elif p["kind"] == "chat":
        advice = _CHAT_ADVICE
    else:
        advice = p.get("advice", [])
    return {
        "id": p["id"],
        "name": p["name"],
        "kind": p["kind"],
        "mha_ticks": ticks,
        "mha_ratings_url": RATINGS_URL if ticks is not None else None,
        "ratings_checked": RATINGS_CHECKED if ticks is not None else None,
        "advice": list(advice),
    }

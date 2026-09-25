# Shop analyzer

`usi/shop/` answers a narrower question than the URL investigation: is this online shop likely to take
the money and send nothing? The URL layers were built for phishing and malware. Fake shops don't steal
logins, so on a set of eight shops confirmed fake by Watchlist Internet the URL verdict alone flagged
none (2026-09-25). The shop analyzer adds the checks that matter for shops and turns them into a risk
band with named reasons.

```bash
python -m usi.shop walkingmats.com
python -m usi.shop some-shop.sg --paid-by paynow --advertised-on instagram --json
```

```python
from usi.config import load_config
from usi.shop.analyzer import investigate_shop

result = investigate_shop("some-shop.sg", load_config(), buyer_claims={"payment_requested": "paynow"})
result["risk_band"], result["rules"], result["signals"], result["checklist"]
```

## What it checks

| Group (`source`) | Check | Signal codes |
|---|---|---|
| How long it has existed (`shop_age`) | Domain age from WHOIS, or RDAP where WHOIS has nothing (all `.sg` domains) | `shop_domain_new` (< 90 days, MEDIUM), `shop_domain_recent` (< 1 year, LOW) |
| | Age of the product catalogue (Shopify `created_at`) | `shop_catalogue_new` (< 60 days; MEDIUM unless the domain is known to be over a year old) |
| How it takes your money (`shop_money`) | Discount depth, measured from the public product feed (Shopify `/products.json`, WooCommerce Store API) or, failing that, from "-70%" badges | `shop_deep_discounts` |
| | Payment methods shown before checkout: card logos from the HTML, transfers and crypto from the visible text | `shop_prepayment_only`, `shop_payment_irreversible` |
| Who is behind it (`shop_identity`) | Email, phone and street address on the front, contact, about, returns and terms pages | `shop_no_contact`, `shop_contact_thin`, `shop_freemail_contact` |
| | Returns/refund and terms pages linked | `shop_no_policies` |
| | Singapore UEN shown on the site, looked up in ACRA's register | `shop_uen_not_found`, `shop_uen_deregistered`, `shop_uen_name_mismatch`, `shop_uen_recent`, `shop_sg_no_uen` |
| Is it a copy (`shop_copy`) | A retailer's name in the web address, or "official store" claims (`data/retail_brands.json`) | `shop_brand_in_address`, `shop_official_claim` |
| | Template placeholder text left in the pages ("[Store Name]", lorem ipsum) | `shop_template_text` |
| | Trust badges that don't link to their issuer | `shop_seal_unlinked` |
| What the buyer told us (`shop_claims`) | How the seller asked to be paid; the price seen against the usual price | `claim_payment_irreversible`, `claim_payment_transfer`, `claim_deep_discount` |

Everything is a normal `Signal`; INFO signals record what was checked and found in order.

## Risk bands (`usi/shop/rules.py`)

Named rules, never a summed score. The band is the highest any rule reaches, and every rule that fired is
returned with its reason.

- **High**: a registration number that isn't a registered business; being asked to pay by crypto or gift
  cards; or a newness sign (`shop_domain_new`, `shop_catalogue_new`, `shop_uen_recent`) together with an
  unprotected payment method, deep discounts, or a borrowed brand name; or three separate MEDIUM signs.
- **Elevated**: one MEDIUM sign, three minor (LOW) signs together, or a HIGH finding from the URL
  investigation.
- **Low**: nothing found. **Not enough information**: the page couldn't be examined and nothing else fired.

The URL engine's embedding classifier is not used for shop bands: it scores genuine shops as high as
scam pages (see `content/classifier.py`), and on the evaluation set it raised a HIGH "malware-risk" on a
genuine coffee retailer.

## Links to marketplaces, social media and chat apps

A Shopee, Lazada, Amazon, TikTok Shop, Carousell or Facebook Marketplace link is a genuine platform; the
risk is the seller. Such links get `risk_band: "Check the seller"`, the platform's Transaction Safety
Rating from MHA where it has one (4 ticks: Amazon, Lazada, Shopee, TikTok Shop; 2: Carousell; 1: Facebook
Marketplace; checked 2026-09-25), and advice for buying safely there. Instagram, Facebook pages, TikTok
videos, Telegram and WhatsApp links get the social / chat advice. Nothing is fetched for these.

## What counts as "examined"

The main page is judged only if it came back 2xx and isn't a bot-protection page ("Just a moment...",
"Attention Required! | Cloudflare"). Many shops sit behind Cloudflare and would otherwise read as having
no contact details. When the page can't be examined, the checks that need only the address still run
(domain age, brand name in the address).

Contact and policy absence is only weighed when the front page was readable and its footer links came
through. Pages built entirely by script, pages longer than the fetch cap (`fetch_max_bytes`), and pages
whose footer is loaded by script get an INFO or LOW note instead of `shop_no_contact`.

## Singapore business register (UEN)

`identity.py` looks UENs up in a local copy of ACRA's register when `data/acra_entities.sqlite3` (or
`USI_ACRA_DB`) exists, and otherwise in data.gov.sg's API (`USI_DATAGOVSG_API_KEY` optional). The API
rate-limits unauthenticated callers after about five requests, so a public deployment should build the
local copy and refresh it weekly:

```bash
python scripts/update_acra.py            # ~300 MB, 2.12 million entities, a few minutes
```

The published data lags by about two weeks (newest registration on 2026-09-25: 2026-09-11), so a
company-format UEN numbered this year that isn't found yet is only a LOW sign.

## Evaluation

`scripts/eval_shop.py` runs the analyzer over `data/shop_eval.csv`: 40 shops from Watchlist Internet's
expert-checked list of fraudulent shops, 22 independent Singapore shops, 3 Singapore retailers, 8
German-language shops and 2 marketplaces. Run on 2026-09-25:

| Group | Page loaded | Flagged (High or Elevated) |
|---|---|---|
| Fake shops | 23 of 40 | 19 of 23 (83%), 6 High; 32 of all 40 counting address-only checks |
| Independent Singapore shops | 21 | 0 |
| Singapore retailers | 3 | 0 |
| German-language shops | 5 | 0 |
| Marketplaces | - | 2 of 2 answered as platforms |

The same set was used to tune the rules (the bot-page, script-built-page and "everything on sale"
handling all came from it), so these figures are optimistic. The next evaluation needs a held-out set.
For comparison, the URL verdict alone flagged 0 of the 8 fake shops tested on the same day.

Known gaps: German B2B-style fake shops (machinery, firewood, heating oil) with a complete-looking
imprint, working card payments and no discounts are not caught; `.de` and `.at` registries publish no
registration date, so their age is unknown. Shops behind strict bot protection are only checked by
address. Network matching (shared templates, images and hosting across fake shops) and a rendering
browser are the next steps.

## Guardrails

Same as the rest of the tool: GET requests only (at most four linked pages and one product feed per
shop), capped size and time, the configured User-Agent, the internal-address guard. It never adds to a
cart, submits a form or opens a checkout. Reports state what was found, never that a shop "is a scam".

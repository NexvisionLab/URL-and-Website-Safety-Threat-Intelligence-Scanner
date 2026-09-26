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

## Rendering in a browser (`usi/shop/browser.py`, `usi/shop/render.py`)

Optional. With `USI_RENDER_URL` (a render service, as DarkNyx runs it) or `USI_RENDER_LOCAL=1`
(`pip install -r requirements-render.txt`, then `playwright install chromium`, or point `USI_CHROMIUM_PATH`
at an installed Chrome), the analyzer uses headless Chromium in two cases:

- **The plain fetch can't read the shop:** the page is built by script, or its footer (contact and policy
  links) is added by script. The rendered page is then read instead. Its linked pages are still fetched
  plainly, so missing contact details on a rendered shop are only noted (`shop_contact_not_found`),
  never weighed.
- **Every shop gets a second look as a phone visitor arriving from a Facebook link.** Some fake-shop
  campaigns show their storefront only to that visitor and an error page to everyone else:
  - `shop_cloaked_for_ads` (HIGH): an error or blank page for the plain visitor, a storefront for the
    phone-from-Facebook visitor;
  - `shop_redirects_ad_visitors` (MEDIUM): phone visitors are sent to a different website.

  A bot check on either view is not treated as cloaking.

One product page (`/products/...`, `/product/...`, ...) now joins the linked pages read for payment and
contact details.

The browser only looks:
- it never clicks, types or submits, and refuses downloads;
- it doesn't load images, media or fonts;
- it refuses every request to a non-public address, including requests from the page's own scripts and
  WebSockets. Tested 2026-09-26: a page's scripts trying `fetch` to localhost, `fetch` to 192.168.1.1 and
  a WebSocket to localhost produced no connection at a listener on the target port;
- it identifies as headless Chrome. The phone view uses a phone's user agent, because that view is the
  point of the check. Nothing is masked and no bot check is solved, so a shop behind an interactive
  challenge stays unexamined.

Measured on genuine shops:
- tangs.com's script-added footer now yields its phone number and address;
- limcheeguan.sg's script-built page is read;
- the phone-from-Facebook view matched the plain one for every genuine shop tried.

## Evidence from the address alone (`usi/shop/address.py`)

About half the fake shops in the evaluations couldn't be examined: they answered with a bot check or were
already down. An honest browser doesn't help there (tested 2026-09-26 with headless Chromium, no evasion:
Cloudflare-protected shops stayed blocked), and this tool doesn't try to get around bot protection. What
the address itself shows still counts:

| Check | Signal |
|---|---|
| First certificate in Certificate Transparency logs (crt.sh) - an age even for `.de`/`.at` domains, whose registries publish none | `shop_cert_new` (< 90 days, MEDIUM; counts as a newness sign), `shop_old_domain_new_site` (domain 2+ years old, first certificate < 90 days: an old address only now used as a website, LOW) |
| A name that reads as random letters, scored against letter pairs of real website names (`data/name_bigrams.json`, built from the Tranco list by `scripts/build_name_model.py`) | `shop_random_name` (LOW) |
| The server is one that security researchers published as hosting a fake-shop network (`data/fake_shop_hosting.json`; exact addresses only) | `shop_known_fake_hosting` (MEDIUM) |

The certificate lookup is best-effort. crt.sh is a free community service and was often overloaded when
this was measured (2026-09-26: 6-16 s for small shops, 502 errors, and timeouts on large sites with
thousands of certificates - 44 of 53 genuine shops got no answer). It is capped at 10 s, runs alongside the
page checks, and a failed lookup is only noted. A dependable source would be our own record of the
certificate logs (for example certstream on the server), which belongs with the network-matching work.

On the 51 genuine shops in the evaluation files none of the three address checks fired; the one genuine shop
flagged (littlefarms.com) is flagged by the URL investigation's `brand_impersonation` rule, as before.

The random-name score is deliberately a minor sign: on names of 6-9 random letters it catches about a third
at a cut-off that flags 0.5% of real website names, and short names carry too little evidence. It matters in
combination: a new shop with a generated name is High, and two address signs on a blocked page are Elevated.

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

`scripts/eval_shop.py` runs the analyzer over `data/shop_eval.csv` (22 independent Singapore shops, 3
Singapore retailers, 8 German-language shops, 2 marketplaces) plus any confirmed-fake lists in
`data/private/` (git-ignored). The fake shops used below came from Watchlist Internet's expert-checked
list of fraudulent shops; its terms don't allow republishing the list without the publisher's consent,
so it is not in this repository. Run on 2026-09-25, with 40 of those fake shops:

| Group | Page loaded | Flagged (High or Elevated) |
|---|---|---|
| Fake shops | 23 of 40 | 19 of 23 (83%), 6 High; 32 of all 40 counting address-only checks |
| Independent Singapore shops | 21 | 0 |
| Singapore retailers | 3 | 0 |
| German-language shops | 5 | 0 |
| Marketplaces | - | 2 of 2 answered as platforms |

The same set was used to tune the rules (the bot-page, script-built-page and "everything on sale"
handling all came from it), so these figures are optimistic.

Held-out check, 2026-09-26, with the rules unchanged: the 40 most recently listed fake shops that were
not in the first set (listed 18-25 September, taken in list order) and 20 more independent Singapore
shops, each matched to a registered company in ACRA's register:

| Group | Page loaded | Flagged (High or Elevated) |
|---|---|---|
| Fake shops | 19 of 40 | 14 of 19 (74%), 4 High; 21 of all 40 (53%) |
| Independent Singapore shops | 20 | 1 (5%) - by the URL investigation's `brand_impersonation` rule ("Apple" on a page with a login field), not by a shop rule |

The drop comes mostly from fake shops whose page can't be examined (bot checks, sites already down)
and whose domains are 3-12 months old, which leaves only a minor age sign. A rendering browser (next
phase) is the biggest lever.
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

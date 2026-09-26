# Changelog

## Unreleased

### Added
- Network matching for the shop analyzer (`usi/shop/fingerprint.py`):
  - **Fingerprints:** tracking accounts, the Shopify store name, contact email and phone, UEN, and the
    server address (except on shared platforms, `data/shared_hosting.json`).
  - **What is kept:** only shops that showed warning signs of their own, kept for a year in
    `USI_SHOP_NETWORK_DB`. Clean shops are not recorded, nothing records who asked, and reports carry
    counts only.
  - **Signals:** `shop_network_high_risk` (MEDIUM), plus the `network_with_high_risk_shops` rule for new or
    otherwise suspicious shops.
  - **Established clean shops:** they can't be raised by network evidence (`shop_network_copied`), because
    fakes copy real shops.
- Optional browser rendering for the shop analyzer (`usi/shop/browser.py`, `usi/shop/render.py`,
  `requirements-render.txt`):
  - script-built pages and script-added footers are read through headless Chromium;
  - every shop gets a phone-from-Facebook view, to catch storefronts shown only to ad visitors
    (`shop_cloaked_for_ads`, `shop_redirects_ad_visitors`);
  - one product page joins the linked pages read.

  The browser refuses every request to non-public addresses, WebSockets included, and never clicks,
  submits or evades bot checks. Enabled with `USI_RENDER_URL` (render service) or `USI_RENDER_LOCAL=1`.
- Address-level shop evidence (`usi/shop/address.py`) for shops whose page can't be examined: first
  certificate date from Certificate Transparency logs, random-letter names (letter-pair model built from
  the Tranco list, `scripts/build_name_model.py`), and servers published as fake-shop hosting
  (`data/fake_shop_hosting.json`, Malwarebytes, March 2026). New rules: a new shop with a generated name
  or on known fake-shop hosting is High; two address signs on a blocked page are Elevated.
- Shop analyzer (`usi/shop/`, `python -m usi.shop`): registration and catalogue age, discount depth
  from Shopify and WooCommerce product feeds, payment methods, contact details and policies, template
  leftovers, unlinked trust badges, retailer names in the address, and Singapore UEN checks against
  ACRA's register. Named rules turn the evidence into a High / Elevated / Low band. Marketplace,
  social-media and chat links get MHA's platform safety rating and seller advice instead of a verdict.
  See `docs/shop-analyzer.md`.
- `usi/lookups/rdap.py`: RDAP registration lookup through IANA's bootstrap list.
- `scripts/eval_shop.py` with `data/shop_eval.csv` (33 genuine shops, 2 marketplaces; confirmed
  fake-shop lists are read from the git-ignored `data/private/`, because their publishers' terms
  don't allow republishing them), and `scripts/update_acra.py` to build a local copy of ACRA's register.
- `pipeline.run(page_sink=...)`: hands the fetched page to a caller that analyses it further.

### Changed
- The cloaking check no longer reports a size difference between two short responses (both under 2 KB,
  typically block or error pages when a site refuses the server) as cloaking; it reports
  `cloaking_check_inconclusive` instead. Found live: a genuine retailer that blocks the scanner's
  address was flagged HIGH on 118 vs 520 bytes, turning both the URL and shop verdicts to a warning.
- WHOIS falls back to RDAP when python-whois returns no registration data, so `.sg` domains (and
  other ccTLDs python-whois can't parse) now get a domain age. Signal codes are unchanged; the
  evidence carries `"via": "rdap"`.

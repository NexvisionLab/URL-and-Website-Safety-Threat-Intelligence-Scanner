# Changelog

## Unreleased

### Added
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

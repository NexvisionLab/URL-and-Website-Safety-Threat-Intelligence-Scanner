# Changelog

## Unreleased

### Added
- Shop analyzer (`usi/shop/`, `python -m usi.shop`): registration and catalogue age, discount depth
  from Shopify and WooCommerce product feeds, payment methods, contact details and policies, template
  leftovers, unlinked trust badges, retailer names in the address, and Singapore UEN checks against
  ACRA's register. Named rules turn the evidence into a High / Elevated / Low band. Marketplace,
  social-media and chat links get MHA's platform safety rating and seller advice instead of a verdict.
  See `docs/shop-analyzer.md`.
- `usi/lookups/rdap.py`: RDAP registration lookup through IANA's bootstrap list.
- `scripts/eval_shop.py` with `data/shop_eval.csv` (40 confirmed fake shops, 33 genuine shops,
  2 marketplaces), and `scripts/update_acra.py` to build a local copy of ACRA's register.
- `pipeline.run(page_sink=...)`: hands the fetched page to a caller that analyses it further.

### Changed
- WHOIS falls back to RDAP when python-whois returns no registration data, so `.sg` domains (and
  other ccTLDs python-whois can't parse) now get a domain age. Signal codes are unchanged; the
  evidence carries `"via": "rdap"`.

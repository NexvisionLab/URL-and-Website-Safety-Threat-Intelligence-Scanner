"""python -m usi.shop <url> [--paid-by paynow] [--json]: run the shop analyzer from the command line."""
import argparse
import json
import sys

from ..config import load_config
from ..pipeline import InvalidTargetError
from .analyzer import investigate_shop
from .claims import ADVERT_CHOICES, PAYMENT_CHOICES


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m usi.shop", description="Check an online shop for warning signs.")
    p.add_argument("url", help="The shop's web address")
    p.add_argument("--paid-by", choices=sorted(PAYMENT_CHOICES), help="How the seller asked to be paid")
    p.add_argument("--advertised-on", choices=sorted(ADVERT_CHOICES), help="Where you saw the shop")
    p.add_argument("--price", type=float, help="The price you saw")
    p.add_argument("--usual-price", type=float, help="What the item usually costs")
    p.add_argument("--refresh", action="store_true", help="Ignore any cached result")
    p.add_argument("--json", action="store_true", help="Print the full result as JSON")
    args = p.parse_args(argv)

    claims = {"payment_requested": args.paid_by, "advertised_on": args.advertised_on,
              "price_seen": args.price, "usual_price": args.usual_price}
    try:
        result = investigate_shop(args.url, load_config(), buyer_claims=claims, no_cache=args.refresh)
    except InvalidTargetError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return 0
    print(f"{result['host']}: {result['risk_band']}")
    for rule in result["rules"]:
        print(f"  [{rule['band']}] {rule['reason']}")
    for s in result["signals"]:
        if s["severity"] != "INFO":
            print(f"  - ({s['severity'].lower()}) {s['message']}")
    if result.get("platform"):
        print("  " + "\n  ".join(result["checklist"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())

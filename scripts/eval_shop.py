"""Measures the shop analyzer against a labelled list of shops.

    python scripts/eval_shop.py                      # run the analyzer here
    python scripts/eval_shop.py --api https://darknyx.com/api/tools/check-shop
    python scripts/eval_shop.py --only fake --workers 4 --out results.json

data/shop_eval.csv lists genuine shops - weighted towards small
independent Singapore sellers, which are the hard case - and
marketplaces, which must get the platform answer rather than a verdict.
Confirmed fake shops are not in the repository: the lists they come
from (e.g. Watchlist Internet's) may not be republished without the
publisher's consent. Put them in data/private/*.csv (git-ignored, same
columns) and they are read too; --csv replaces all of this with the
files given.

"Flagged" means a High or Elevated band. The targets in the design are
at least 80% of fakes flagged and at most 2% of genuine small Singapore
shops flagged. Shops that couldn't be loaded are counted separately:
fake shops disappear quickly, and an unreachable one says nothing about
the rules. Every run makes live requests to every listed shop."""
import argparse
import csv
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FLAGGED = {"High", "Elevated"}


def run_local(url: str) -> dict:
    from usi.config import load_config
    from usi.shop.analyzer import investigate_shop
    return investigate_shop(url, load_config(), no_cache=True, no_store=True)


def run_api(api: str, url: str) -> dict:
    import requests
    resp = requests.post(api, json={"url": url}, timeout=150)
    return resp.json()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--csv", type=Path, action="append",
                   help="Evaluation file(s); default: data/shop_eval.csv plus data/private/*.csv")
    p.add_argument("--api", help="POST each URL to this check-shop endpoint instead of running locally")
    p.add_argument("--only", help="Only rows with this label (fake, real, platform)")
    p.add_argument("--workers", type=int, default=3)
    p.add_argument("--out", type=Path, help="Write every result as JSON here")
    args = p.parse_args(argv)

    files = args.csv or [ROOT / "data" / "shop_eval.csv", *sorted((ROOT / "data" / "private").glob("*.csv"))]
    rows = []
    for path in files:
        with open(path, encoding="utf-8") as f:
            rows += [r for r in csv.DictReader(f) if not args.only or r["label"] == args.only]

    def check(row):
        started = time.monotonic()
        try:
            result = run_api(args.api, row["url"]) if args.api else run_local(row["url"])
        except Exception as e:  # noqa: BLE001 - one broken shop must not stop the run
            result = {"error": f"{type(e).__name__}: {e}"}
        result["_seconds"] = round(time.monotonic() - started, 1)
        return row, result

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(check, rows))

    print(f"{'shop':34} {'label':9} {'band':24} rules / warnings")
    for row, r in results:
        band = r.get("risk_band") or ("error: " + r.get("error", "?"))[:24]
        if r.get("page_examined") is False and r.get("kind") == "shop":
            band += " (not loaded)"
        rules = ",".join(x["id"] for x in r.get("rules", []))
        warn = ",".join(s["code"] for s in r.get("signals", []) if s.get("severity") != "INFO")
        print(f"{row['url'][:34]:34} {row['label']:9} {band[:24]:24} {rules} | {warn}")

    def rate(label, group=None):
        sel = [(row, r) for row, r in results if row["label"] == label and (group is None or row["group"] == group)]
        loaded = [(row, r) for row, r in sel if r.get("page_examined")]
        flagged = [x for x in loaded if x[1].get("risk_band") in FLAGGED]
        high = [x for x in loaded if x[1].get("risk_band") == "High"]
        return len(sel), len(loaded), len(flagged), len(high)

    print()
    n, loaded, flagged, high = rate("fake")
    if n:
        print(f"fake shops: {n} listed, {loaded} loaded; flagged {flagged}/{loaded}"
              f" ({flagged / loaded:.0%}), High {high}" if loaded else f"fake shops: {n} listed, none loaded")
    for group in sorted({row["group"] for row, _ in results if row["label"] == "real"}):
        n, loaded, flagged, high = rate("real", group)
        if loaded:
            print(f"genuine ({group}): {loaded} loaded; flagged {flagged} ({flagged / loaded:.0%}), High {high}")
    platforms = [(row, r) for row, r in results if row["label"] == "platform"]
    if platforms:
        ok = sum(1 for _, r in platforms if r.get("risk_band") == "Check the seller")
        print(f"marketplaces answered as platforms: {ok}/{len(platforms)}")

    if args.out:
        args.out.write_text(json.dumps([{"row": row, "result": r} for row, r in results], indent=1, default=str),
                            encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

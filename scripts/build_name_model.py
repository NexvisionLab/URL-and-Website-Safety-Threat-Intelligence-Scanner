"""Builds data/name_bigrams.json, the letter-pair model behind the shop
analyzer's "random-letter name" check (usi/shop/address.py).

    python scripts/build_name_model.py path/to/tranco-top-1m.csv.zip

The model is letter-pair counts over the names of popular real websites:
the Tranco list (https://tranco-list.eu/), ranks 1-200,000. Only the
counts are stored, not the list. Names like "bnbsjbir" or "vxjskiy" are
made of letter pairs that real names almost never use, which is what the
check measures."""
import csv
import io
import json
import re
import sys
import zipfile
from pathlib import Path

import tldextract

ROOT = Path(__file__).resolve().parent.parent
ALPHABET = "^abcdefghijklmnopqrstuvwxyz$"
TRAIN_RANKS = 200_000

_extract = tldextract.TLDExtract(suffix_list_urls=())


def tokens(domain: str) -> "list[str]":
    label = _extract(domain).domain.lower()
    return [t for t in re.split(r"[^a-z]+", label) if len(t) >= 3]


def main(argv=None) -> int:
    src = Path((argv or sys.argv[1:])[0])
    with zipfile.ZipFile(src) as z:
        rows = csv.reader(io.TextIOWrapper(z.open(z.namelist()[0]), encoding="utf-8"))
        counts = [[0] * len(ALPHABET) for _ in ALPHABET]
        n = 0
        for rank, domain in rows:
            if int(rank) > TRAIN_RANKS:
                break
            for tok in tokens(domain):
                s = "^" + tok + "$"
                for a, b in zip(s, s[1:]):
                    counts[ALPHABET.index(a)][ALPHABET.index(b)] += 1
                n += 1
    out = ROOT / "data" / "name_bigrams.json"
    out.write_text(json.dumps({"_comment": "Letter-pair counts over name tokens of Tranco ranks 1-200,000 "
                                           "(https://tranco-list.eu/); built by scripts/build_name_model.py.",
                               "alphabet": ALPHABET, "tokens": n, "counts": counts}), encoding="utf-8")
    print(f"{n} name tokens -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

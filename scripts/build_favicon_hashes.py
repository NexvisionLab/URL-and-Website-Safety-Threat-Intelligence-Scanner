"""One-off/maintenance script: builds data/favicon_hashes.json by fetching
each brand's real homepage, parsing its declared <link rel="icon"> (falling
back to /favicon.ico only if no link tag is found), and hashing the actual
favicon bytes. Re-fetches each candidate twice with a short delay and only
keeps it if the hash is stable, since favicon fetches were observed to be
occasionally inconsistent (CDN edge-cache variance) during initial testing -
shipping an unverified/unstable hash would silently break the detection
it's meant to power.

Run manually, not part of the CLI's runtime path:
    python scripts/build_favicon_hashes.py
"""
import hashlib
import json
import time
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parent.parent
USER_AGENT = "url-safety-investigator/0.1 (local research tool)"
TIMEOUT = 10
STABILITY_RECHECK_DELAY = 2


def find_declared_favicon_url(homepage_url: str) -> "str | None":
    try:
        resp = requests.get(homepage_url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
    except requests.RequestException:
        return None
    soup = BeautifulSoup(resp.text, "lxml")
    for rel in ("icon", "shortcut icon", "apple-touch-icon"):
        link = soup.find("link", rel=lambda v: v and rel in v.lower() if v else False)
        if link and link.get("href"):
            return urljoin(resp.url, link["href"])
    return urljoin(resp.url, "/favicon.ico")


def fetch_and_hash(favicon_url: str) -> "tuple[str, int] | None":
    try:
        resp = requests.get(favicon_url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT})
        if resp.status_code != 200 or len(resp.content) < 50:
            return None
        return hashlib.md5(resp.content).hexdigest(), len(resp.content)
    except requests.RequestException:
        return None


def main():
    with open(ROOT / "data" / "brands.json", encoding="utf-8") as f:
        brands = json.load(f)["brands"]

    results = {}
    for brand in brands:
        name = brand["name"]
        domain = brand["domains"][0]
        homepage = f"https://{domain}/"

        favicon_url = find_declared_favicon_url(homepage)
        if not favicon_url:
            print(f"{name}: FAILED (could not load homepage)")
            continue

        first = fetch_and_hash(favicon_url)
        if not first:
            print(f"{name}: FAILED (favicon fetch at {favicon_url})")
            continue
        time.sleep(STABILITY_RECHECK_DELAY)
        second = fetch_and_hash(favicon_url)
        if not second or first[0] != second[0]:
            print(f"{name}: SKIPPED (unstable hash across two fetches - {favicon_url})")
            continue

        md5_hash, size = first
        results[name] = {"domain": domain, "favicon_url": favicon_url, "md5": md5_hash, "size": size}
        print(f"{name}: OK ({size} bytes, md5={md5_hash[:12]}..., stable) -> {favicon_url}")

    out_path = ROOT / "data" / "favicon_hashes.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({
            "_comment": "Brand -> real favicon MD5 hash, built by scripts/build_favicon_hashes.py. "
                        "Only includes brands whose favicon hash was verified stable across two "
                        "fetches. Re-run periodically - brands rotate favicons occasionally.",
            "favicons": results,
        }, f, indent=2)
    print(f"\nWrote {len(results)}/{len(brands)} verified favicon hashes to {out_path}")


if __name__ == "__main__":
    main()

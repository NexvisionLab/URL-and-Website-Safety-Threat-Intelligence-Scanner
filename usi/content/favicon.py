"""Favicon hash matching: fetches the investigated site's favicon and
compares its MD5 against data/favicon_hashes.json (real brand favicons,
verified stable - see scripts/build_favicon_hashes.py). A byte-identical
favicon on a domain that isn't the brand's own is a strong, well-
documented phishing signal (parasitic favicon reuse) - and critically,
it works even on JavaScript-rendered pages a plain HTTP fetch can't see
into, since the favicon is a static asset referenced in <head> before
any JS runs. Example: an OpenPhish-listed DHL phishing clone served a
favicon byte-identical (same MD5) to DHL's own, even though its login
form was invisible to this tool's non-JS fetcher."""
import hashlib
import json
from pathlib import Path
from urllib.parse import urljoin

import requests

from .. import netguard
from ..models import Severity, Signal
from ..net import build_session

DEFAULT_HASHES_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "favicon_hashes.json"
FAVICON_FETCH_TIMEOUT = 10
MAX_FAVICON_BYTES = 200_000


def load_favicon_hashes(path: "Path | None" = None) -> "dict[str, dict]":
    path = path or DEFAULT_HASHES_PATH
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("favicons", {})


def find_declared_favicon_url(raw_html: "str | None", base_url: str) -> str:
    if raw_html:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(raw_html, "lxml")
            for rel in ("icon", "shortcut icon", "apple-touch-icon"):
                link = soup.find("link", rel=lambda v: v and rel in v.lower() if v else False)
                if link and link.get("href"):
                    return urljoin(base_url, link["href"])
        except Exception:  # noqa: BLE001 - fall through to the /favicon.ico default
            pass
    return urljoin(base_url, "/favicon.ico")


def check(
    host: str,
    favicon_url: str,
    user_agent: str,
    brands: "list[dict]",
    known_hashes: "dict[str, dict] | None" = None,
    tor_proxy: "str | None" = None,
) -> "Signal | None":
    known_hashes = known_hashes if known_hashes is not None else load_favicon_hashes()
    if not known_hashes:
        return None

    try:
        proxies = {"http": tor_proxy, "https": tor_proxy} if tor_proxy else None
        if netguard.enabled() and not tor_proxy:
            # A page chooses its own favicon address, so it must not be able to aim this fetch inward.
            getter = build_session(user_agent).get
            resp = getter(favicon_url, timeout=FAVICON_FETCH_TIMEOUT, stream=True)
        else:
            resp = requests.get(
                favicon_url, timeout=FAVICON_FETCH_TIMEOUT, proxies=proxies,
                headers={"User-Agent": user_agent}, stream=True,
            )
        if resp.status_code != 200:
            return None
        content = resp.raw.read(MAX_FAVICON_BYTES, decode_content=True)
        if len(content) < 50:
            return None
        site_hash = hashlib.md5(content).hexdigest()
    except requests.RequestException:
        return None

    brand_domains_by_name = {b["name"]: [d.lower() for d in b["domains"]] for b in brands}
    host_l = host.lower()

    for brand_name, entry in known_hashes.items():
        if entry.get("md5") != site_hash:
            continue
        real_domains = brand_domains_by_name.get(brand_name, [entry.get("domain", "").lower()])
        if host_l in real_domains or any(host_l.endswith("." + d) for d in real_domains):
            return None  # this IS the real brand's own site
        return Signal(
            source="favicon", code="favicon_matches_brand", severity=Severity.CRITICAL,
            message=(
                f"This site's favicon is byte-identical to {brand_name}'s real favicon, "
                f"but it is served from '{host}', which is not a known {brand_name} domain "
                "- a classic parasitic favicon reuse pattern seen in phishing clones."
            ),
            evidence={"brand": brand_name, "host": host, "favicon_md5": site_hash},
        )

    return None

"""RDAP registration lookup - the structured, JSON successor to WHOIS.

Why it exists: python-whois returns nothing usable for several ccTLDs,
.sg among them, so a Singapore shop's domain age was simply missing.
Every gTLD registry and many ccTLD registries (SGNIC included) answer
RDAP, and IANA publishes which server answers for which TLD.

Used two ways: as the fallback when WHOIS gives no registration data
(whois_lookup.py), and directly by the shop analyzer, which also wants
the "last changed" date and, where the registry publishes it (SGNIC
does), the registrant's name.

Every failure returns None - the caller decides what "unavailable"
means. GET-only, bounded timeout, like every other lookup here."""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import tldextract

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_MAX_AGE_SECONDS = 7 * 24 * 3600
TIMEOUT_SECONDS = 10

# Used when the IANA bootstrap file can't be fetched. Checked against
# dns.json on 2026-09-25; the bootstrap is the source of truth.
_FALLBACK_SERVERS = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "sg": "https://rdap.sgnic.sg/rdap/",
    "shop": "https://rdap.gmoregistry.net/rdap/",
}

_DEFAULT_CACHE_DIR = Path(__file__).resolve().parent.parent.parent / "cache"
_bootstrap_memo: "dict[str, str] | None" = None

# No suffix-list download at runtime: tldextract's bundled snapshot is enough
# to find the registrable domain, and a lookup must not stall on it.
_extract = tldextract.TLDExtract(suffix_list_urls=())


def registrable_domain(host: str) -> "str | None":
    ext = _extract(host.lower().rstrip("."))
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"


def _load_bootstrap(cache_dir: Path) -> "dict[str, str]":
    global _bootstrap_memo
    if _bootstrap_memo is not None:
        return _bootstrap_memo
    path = cache_dir / "rdap_bootstrap.json"
    data = None
    try:
        if path.exists() and time.time() - path.stat().st_mtime < BOOTSTRAP_MAX_AGE_SECONDS:
            data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = None
    if data is None:
        try:
            resp = requests.get(BOOTSTRAP_URL, timeout=TIMEOUT_SECONDS)
            resp.raise_for_status()
            data = resp.json()
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(data), encoding="utf-8")
            except OSError:
                pass
        except (requests.RequestException, ValueError):
            data = None
    servers: "dict[str, str]" = dict(_FALLBACK_SERVERS)
    for tlds, urls in (data or {}).get("services", []):
        https = [u for u in urls if u.startswith("https://")]
        if not https:
            continue
        for tld in tlds:
            servers[tld.lower()] = https[0] if https[0].endswith("/") else https[0] + "/"
    _bootstrap_memo = servers
    return servers


def _parse_date(value: "str | None") -> "datetime | None":
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _vcard_name(entity: dict) -> "str | None":
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn" and isinstance(item[3], str):
            name = item[3].strip()
            return name or None
    return None


def parse(data: dict) -> dict:
    """Turns an RDAP domain object into the few fields this tool uses."""
    events = {}
    for ev in data.get("events") or []:
        action = str(ev.get("eventAction", "")).lower()
        if action and action not in events:
            events[action] = _parse_date(ev.get("eventDate"))
    registrar = registrant = None
    for ent in data.get("entities") or []:
        roles = [str(r).lower() for r in ent.get("roles") or []]
        if "registrar" in roles and registrar is None:
            registrar = _vcard_name(ent)
        if "registrant" in roles and registrant is None:
            name = _vcard_name(ent)
            # Redacted registrants come back as a placeholder, not a name.
            if name and "redacted" not in name.lower() and "privacy" not in name.lower():
                registrant = name
    return {
        "created": events.get("registration"),
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "registrar": registrar,
        "registrant": registrant,
    }


def registration(host: str, cache_dir: "Path | None" = None) -> "dict | None":
    """Registration data for the host's registrable domain, or None when
    RDAP has no server for its TLD or the lookup fails."""
    domain = registrable_domain(host)
    if not domain:
        return None
    tld = domain.rsplit(".", 1)[-1]
    server = _load_bootstrap(cache_dir or _DEFAULT_CACHE_DIR).get(tld)
    if not server:
        return None
    try:
        resp = requests.get(
            f"{server}domain/{domain}", timeout=TIMEOUT_SECONDS,
            headers={"Accept": "application/rdap+json, application/json"},
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
    except (requests.RequestException, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    result = parse(data)
    if result["created"] is None and result["registrar"] is None:
        return None
    result["domain"] = domain
    result["server"] = server
    return result

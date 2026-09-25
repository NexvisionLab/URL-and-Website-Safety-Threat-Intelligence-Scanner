"""Singapore business identity: the UEN a shop shows, checked against
ACRA's register.

Singapore businesses carry a Unique Entity Number (UEN), and CASE's
e-CaseTrust scheme requires accredited online shops to show their
registered name, UEN and address. ACRA publishes every entity it has
registered as open data on data.gov.sg (dataset DATASET_ID: 2.12 million
entities, status "Registered" or "Deregistered", checked 2026-09-25).

So a UEN on a shop's page can be tested: does it exist, is the business
still registered, and is it the business the shop claims to be? A
number that doesn't exist, or belongs to a deregistered company, is one
of the strongest signs a shop gives. Only ACRA-issued formats are
tested, because only ACRA's entities are in the dataset.

Lookups go to a local copy of the register when one has been built
(scripts/update_acra.py), otherwise to data.gov.sg's API - which rate
limits unauthenticated callers after a few requests, hence the result
cache and the optional USI_DATAGOVSG_API_KEY."""
import json
import os
import re
import sqlite3
import time
from datetime import date, datetime, timezone
from pathlib import Path

import requests

from ..models import Severity, Signal

SOURCE = "shop_identity"
DATASET_ID = "d_3f960c10fed6145404ca7b821f263b87"
API_URL = "https://data.gov.sg/api/action/datastore_search"
API_KEY_ENV = "USI_DATAGOVSG_API_KEY"
LOCAL_DB_ENV = "USI_ACRA_DB"
DEFAULT_LOCAL_DB = Path(__file__).resolve().parent.parent.parent / "data" / "acra_entities.sqlite3"
CACHE_DAYS = 7
TIMEOUT_SECONDS = 10
RECENT_REGISTRATION_DAYS = 180

# ACRA formats: a local company (year + 5 digits + check letter) and a
# business (8 digits + check letter).
_COMPANY = r"(?:19|20)\d{7}[A-Z]"
_BUSINESS = r"\d{8}[A-Z]"
_LABEL = (r"(?i:\bU\.?E\.?N(?:\.|\b)(?:\s*(?:no\.?|number))?|(?:company|business|co\.?)\s*reg(?:istration|n)?\.?"
          r"(?:\s*(?:no\.?|number|#))?|\breg(?:istration)?\.?\s*(?:no\.?|number)|\bROC\s*(?:no\.?)?)")
_LABELLED_RE = re.compile(_LABEL + r"\s*[:：#.\-]?\s*\(?\s*(" + _COMPANY + r"|" + _BUSINESS + r")\b")
# An unlabelled company number right after the company's name: "... Pte. Ltd. (201912345K)".
_AFTER_NAME_RE = re.compile(r"(?i:pte\.?\s*ltd\.?|private limited|\bllp\b)\W{0,6}(" + _COMPANY + r")\b")


def find_uens(texts: "list[str]") -> "list[str]":
    found = []
    this_year = date.today().year
    for text in texts:
        for rx in (_LABELLED_RE, _AFTER_NAME_RE):
            for m in rx.finditer(text or ""):
                uen = m.group(1).upper()
                if re.fullmatch(_COMPANY, uen) and not 1900 <= int(uen[:4]) <= this_year:
                    continue
                if uen not in found:
                    found.append(uen)
    return found[:3]


def looks_singaporean(host: str, texts: "list[str]", phones: "list[str]", addresses: "list[str]") -> bool:
    if host.lower().endswith(".sg"):
        return True
    joined = " ".join(texts)
    if re.search(r"S\$\s?\d|\bSGD\b", joined):
        return True
    if any(p.replace(" ", "").startswith(("+65", "0065")) for p in phones):
        return True
    if any("singapore" in a.lower() for a in addresses):
        return True
    return len(re.findall(r"(?i)\bsingapore\b", joined)) >= 3


# --- register lookups ---------------------------------------------------------------------------

def _local_db_path() -> "Path | None":
    path = Path(os.environ.get(LOCAL_DB_ENV) or DEFAULT_LOCAL_DB)
    return path if path.exists() else None


def _record(row: dict) -> dict:
    return {
        "found": True,
        "uen": row.get("uen"),
        "name": row.get("entity_name"),
        "status": row.get("uen_status_desc"),
        "entity_type": row.get("entity_type_desc"),
        "registered": row.get("uen_issue_date"),
        "postal_code": row.get("reg_postal_code"),
    }


def _lookup_local(path: Path, uen: str) -> "dict | None":
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM entities WHERE uen = ?", (uen,)).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    return _record(dict(row)) if row else {"found": False, "uen": uen}


def _cache_get(cache_path: str, uen: str) -> "dict | None":
    try:
        conn = sqlite3.connect(cache_path)
        try:
            conn.execute("CREATE TABLE IF NOT EXISTS acra_lookups (uen TEXT PRIMARY KEY, looked_up REAL, result TEXT)")
            row = conn.execute("SELECT looked_up, result FROM acra_lookups WHERE uen = ?", (uen,)).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    if row and time.time() - row[0] < CACHE_DAYS * 86400:
        return json.loads(row[1])
    return None


def _cache_set(cache_path: str, uen: str, result: dict) -> None:
    try:
        Path(cache_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(cache_path)
        try:
            conn.execute("CREATE TABLE IF NOT EXISTS acra_lookups (uen TEXT PRIMARY KEY, looked_up REAL, result TEXT)")
            conn.execute("INSERT OR REPLACE INTO acra_lookups VALUES (?, ?, ?)", (uen, time.time(), json.dumps(result)))
            conn.commit()
        finally:
            conn.close()
    except sqlite3.Error:
        pass


def _lookup_api(uen: str) -> "dict | None":
    headers = {}
    if os.environ.get(API_KEY_ENV):
        headers["x-api-key"] = os.environ[API_KEY_ENV]
    try:
        resp = requests.get(API_URL, timeout=TIMEOUT_SECONDS, headers=headers, params={
            "resource_id": DATASET_ID, "filters": json.dumps({"uen": uen}), "limit": 1})
        data = resp.json()
    except (requests.RequestException, ValueError):
        return None
    if resp.status_code != 200 or not isinstance(data, dict) or not data.get("success"):
        return None
    records = (data.get("result") or {}).get("records") or []
    return _record(records[0]) if records else {"found": False, "uen": uen}


def lookup(uen: str, cache_path: str) -> "dict | None":
    """{"found": True, name, status, ...}, {"found": False}, or None when
    the register couldn't be reached."""
    local = _local_db_path()
    if local is not None:
        return _lookup_local(local, uen)
    cached = _cache_get(cache_path, uen)
    if cached is not None:
        return cached
    result = _lookup_api(uen)
    if result is not None:
        _cache_set(cache_path, uen, result)
    return result


# --- signals --------------------------------------------------------------------------------------

_NAME_NOISE = {"pte", "ltd", "private", "limited", "llp", "the", "and", "co", "company", "singapore", "sg",
               "trading", "enterprise", "enterprises", "services", "holdings", "group", "international", "global"}


def _name_tokens(name: str) -> "set[str]":
    return {t for t in re.findall(r"[a-z0-9]+", (name or "").lower()) if len(t) >= 3 and t not in _NAME_NOISE}


def name_appears(name: str, haystack: str) -> bool:
    tokens = _name_tokens(name)
    if not tokens:
        return True
    hay = re.sub(r"[^a-z0-9]", "", haystack.lower())
    return any(t in hay for t in tokens)


def _days_since(iso: "str | None") -> "int | None":
    try:
        d = datetime.fromisoformat(iso).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None
    return (datetime.now(timezone.utc) - d).days


def signals(uens: "list[str]", lookups: "dict[str, dict | None]", singaporean: bool,
            haystack: str) -> "list[Signal]":
    out = []
    if not uens:
        if singaporean:
            out.append(Signal(
                source=SOURCE, code="shop_sg_no_uen", severity=Severity.LOW,
                message=("The shop presents itself as Singaporean but shows no business registration number (UEN). "
                         "Registered shops usually show one; ask for it and look it up on ACRA's BizFile (bizfile.gov.sg)."),
            ))
        return out
    for uen in uens:
        result = lookups.get(uen)
        if result is None:
            out.append(Signal(
                source=SOURCE, code="shop_uen_unavailable", severity=Severity.INFO,
                message=f"The shop shows the UEN {uen}, but ACRA's register couldn't be reached to check it.",
                evidence={"uen": uen},
            ))
            continue
        if not result.get("found"):
            recent = bool(re.fullmatch(_COMPANY, uen)) and int(uen[:4]) >= date.today().year
            out.append(Signal(
                source=SOURCE, code="shop_uen_not_found",
                severity=Severity.LOW if recent else Severity.HIGH,
                message=(f"The shop shows the Singapore registration number {uen}, but no business with that "
                         "number is in ACRA's register." +
                         (" It is numbered as a company registered this year, which may not be in the published "
                          "data yet." if recent else "")),
                evidence={"uen": uen, "register": "ACRA open data (data.gov.sg)"},
            ))
            continue
        name, status = result.get("name") or "", (result.get("status") or "").strip()
        if status.lower() != "registered":
            out.append(Signal(
                source=SOURCE, code="shop_uen_deregistered", severity=Severity.HIGH,
                message=(f"The shop shows the UEN {uen}, which belongs to {name}. ACRA lists that business as "
                         f"'{status}' - it is no longer a registered business."),
                evidence=result,
            ))
            continue
        out.append(Signal(
            source=SOURCE, code="shop_uen_verified", severity=Severity.INFO,
            message=(f"The UEN {uen} is registered to {name} ({result.get('entity_type') or 'business'}), "
                     f"registered since {result.get('registered') or 'an unknown date'}."),
            evidence=result,
        ))
        if not name_appears(name, haystack):
            out.append(Signal(
                source=SOURCE, code="shop_uen_name_mismatch", severity=Severity.LOW,
                message=(f"The UEN {uen} belongs to {name}, but that name doesn't appear anywhere on the shop's pages. "
                         "Check that this is really the business you are buying from."),
                evidence=result,
            ))
        age = _days_since(result.get("registered"))
        if age is not None and age < RECENT_REGISTRATION_DAYS:
            out.append(Signal(
                source=SOURCE, code="shop_uen_recent", severity=Severity.LOW,
                message=f"{name} was registered only {age} day(s) ago.",
                evidence=result,
            ))
    return out

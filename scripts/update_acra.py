"""Builds a local copy of ACRA's register for the shop analyzer's UEN checks.

    python scripts/update_acra.py                       # writes data/acra_entities.sqlite3
    python scripts/update_acra.py --out /srv/acra.sqlite3   # then set USI_ACRA_DB to that path

usi/shop/identity.py looks a UEN up in this file when it exists and only
falls back to data.gov.sg's API otherwise; the API rate-limits callers
without a key after a few requests, so a public deployment should use
the local copy and refresh it on a schedule (weekly is plenty).

Source: "Entities Registered with ACRA" on data.gov.sg (dataset
d_3f960c10fed6145404ca7b821f263b87), downloaded in full through the
dataset's bulk-download API. The new database is built next to the old
one and swapped in only when complete, so lookups never see half a file."""
import argparse
import csv
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
DATASET_ID = "d_3f960c10fed6145404ca7b821f263b87"
BASE = f"https://api-open.data.gov.sg/v1/public/api/datasets/{DATASET_ID}"
COLUMNS = ("uen", "entity_name", "uen_status_desc", "entity_type_desc", "uen_issue_date",
           "reg_postal_code", "reg_street_name", "issuance_agency_desc")


def download_url(session: requests.Session, wait_seconds: int = 180) -> str:
    resp = session.get(f"{BASE}/initiate-download", timeout=30)
    resp.raise_for_status()
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        data = session.get(f"{BASE}/poll-download", timeout=30).json().get("data") or {}
        if data.get("status") == "DOWNLOAD_SUCCESS" and data.get("url"):
            return data["url"]
        time.sleep(3)
    raise RuntimeError("data.gov.sg did not prepare the download in time")


def build(csv_lines, out: Path) -> int:
    tmp = out.with_suffix(".tmp")
    if tmp.exists():
        tmp.unlink()
    conn = sqlite3.connect(tmp)
    conn.execute("CREATE TABLE entities (" + ", ".join(f"{c} TEXT" for c in COLUMNS) + ", PRIMARY KEY (uen))")
    conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
    reader = csv.DictReader(csv_lines)
    missing = [c for c in COLUMNS if c not in (reader.fieldnames or [])]
    if missing:
        conn.close()
        tmp.unlink()
        raise RuntimeError(f"the download is missing columns {missing}; the dataset may have changed")
    rows = 0
    batch = []
    for rec in reader:
        batch.append(tuple((rec.get(c) or "").strip() for c in COLUMNS))
        if len(batch) >= 50_000:
            conn.executemany(f"INSERT OR REPLACE INTO entities VALUES ({', '.join('?' * len(COLUMNS))})", batch)
            rows += len(batch)
            batch = []
    if batch:
        conn.executemany(f"INSERT OR REPLACE INTO entities VALUES ({', '.join('?' * len(COLUMNS))})", batch)
        rows += len(batch)
    newest = conn.execute("SELECT MAX(uen_issue_date) FROM entities").fetchone()[0]
    conn.executemany("INSERT INTO meta VALUES (?, ?)", [
        ("downloaded_at", datetime.now(timezone.utc).isoformat()), ("rows", str(rows)),
        ("newest_issue_date", newest or ""), ("dataset", DATASET_ID)])
    conn.commit()
    conn.close()
    if rows < 1_000_000:
        tmp.unlink()
        raise RuntimeError(f"only {rows} rows downloaded - expected about two million; keeping the old file")
    os.replace(tmp, out)
    return rows


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--out", type=Path, default=ROOT / "data" / "acra_entities.sqlite3")
    args = p.parse_args(argv)
    session = requests.Session()
    url = download_url(session)
    csv_path = args.out.with_suffix(".csv.part")
    fetch_csv(session, url, csv_path)
    try:
        with open(csv_path, encoding="utf-8-sig", newline="") as f:
            rows = build(f, args.out)
    finally:
        csv_path.unlink(missing_ok=True)
    print(f"{rows} entities written to {args.out}")
    return 0


def fetch_csv(session: requests.Session, url: str, path: Path, attempts: int = 4) -> None:
    """The file is a few hundred megabytes and the storage server sometimes drops a long transfer,
    so it is saved to disk first and resumed with a Range request where it stopped."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    total = None
    for _ in range(attempts):
        done = path.stat().st_size if path.exists() else 0
        headers = {"Range": f"bytes={done}-"} if done else {}
        try:
            with session.get(url, stream=True, timeout=60, headers=headers) as resp:
                if resp.status_code not in (200, 206):
                    resp.raise_for_status()
                if resp.status_code == 200:
                    done = 0
                    total = int(resp.headers.get("content-length") or 0) or None
                elif total is None and "/" in resp.headers.get("content-range", ""):
                    total = int(resp.headers["content-range"].rsplit("/", 1)[1])
                with open(path, "ab" if done else "wb") as f:
                    for chunk in resp.iter_content(chunk_size=1 << 20):
                        f.write(chunk)
        except requests.RequestException:
            pass
        if total and path.exists() and path.stat().st_size >= total:
            return
    raise RuntimeError("the download kept breaking off; try again later")


if __name__ == "__main__":
    sys.exit(main())

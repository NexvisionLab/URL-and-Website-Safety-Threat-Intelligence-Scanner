"""SQLite result cache - a single local file. Stores the JSON-serialized
verdict report keyed by normalized URL, with a TTL checked at read time."""
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _connect(path: str) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS investigations (
            url_normalized TEXT PRIMARY KEY,
            checked_at TEXT NOT NULL,
            result_json TEXT NOT NULL
        )
        """
    )
    return conn


def normalize_url(url: str) -> str:
    return url.strip().lower().rstrip("/")


def get(path: str, url: str, ttl_hours: int) -> "dict | None":
    conn = _connect(path)
    try:
        row = conn.execute(
            "SELECT checked_at, result_json FROM investigations WHERE url_normalized = ?",
            (normalize_url(url),),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    checked_at = datetime.fromisoformat(row[0])
    if datetime.now(timezone.utc) - checked_at > timedelta(hours=ttl_hours):
        return None
    return json.loads(row[1])


def list_all(path: str, since_hours: "float | None" = None) -> "list[dict]":
    """Returns every cached result, newest first - used by the report
    generator to build a batch report from investigations already run,
    without re-fetching anything. `since_hours` filters to only entries
    checked within that window; None returns everything regardless of
    the per-entry TTL (a report is a record of what was found, not a
    freshness-gated lookup like get())."""
    conn = _connect(path)
    try:
        rows = conn.execute(
            "SELECT url_normalized, checked_at, result_json FROM investigations "
            "ORDER BY checked_at DESC"
        ).fetchall()
    finally:
        conn.close()

    results = []
    cutoff = None
    if since_hours is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    for url_normalized, checked_at_str, result_json in rows:
        checked_at = datetime.fromisoformat(checked_at_str)
        if cutoff is not None and checked_at < cutoff:
            continue
        results.append(json.loads(result_json))
    return results


def set(path: str, url: str, result: dict) -> None:
    conn = _connect(path)
    try:
        conn.execute(
            """
            INSERT INTO investigations (url_normalized, checked_at, result_json)
            VALUES (?, ?, ?)
            ON CONFLICT(url_normalized) DO UPDATE SET
                checked_at = excluded.checked_at,
                result_json = excluded.result_json
            """,
            (normalize_url(url), datetime.now(timezone.utc).isoformat(), json.dumps(result)),
        )
        conn.commit()
    finally:
        conn.close()

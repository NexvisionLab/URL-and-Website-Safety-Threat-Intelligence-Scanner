"""Shared HTTP session builder: honest User-Agent, optional Tor SOCKS
proxy, and the timeout/byte-cap/redirect-depth conventions used by every
network layer in this tool. GET-only by convention - see
content/fetcher.py's module docstring for the read-only-observation
invariant this tool never crosses."""
import time

import requests

from .netguard import GuardedAdapter

# Bounded redirect depth is a tool-wide invariant (see fetcher.py's
# docstring: "Bounded redirects (max 5 hops)"), not just a fetcher.py-
# specific setting - applied here, in the one shared session builder,
# so every caller (the main fetch and the cloaking comparison fetch)
# gets it automatically instead of falling back to requests' default of
# 30 redirects.
MAX_REDIRECTS = 5


def build_session(user_agent: str, tor_proxy: "str | None" = None) -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})
    session.max_redirects = MAX_REDIRECTS
    if tor_proxy:
        session.proxies.update({"http": tor_proxy, "https": tor_proxy})
    else:
        # Inert unless USI_BLOCK_PRIVATE_ADDRESSES is set; see netguard.py.
        adapter = GuardedAdapter()
        session.mount("http://", adapter)
        session.mount("https://", adapter)
    return session


_READ_CHUNK = 65536


def capped_get(session: requests.Session, url: str, timeout: int, max_bytes: int,
               total_timeout: "float | None" = None):
    """Streams the response and stops reading past max_bytes OR once
    total_timeout seconds (default: 2x timeout) have elapsed, whichever
    comes first. requests' `timeout` only bounds each individual socket
    read, so a hostile server dribbling one byte at a time could
    otherwise hold this tool open indefinitely. The connection is always
    closed. Returns the requests.Response; caller reads
    resp._capped_content instead of resp.content to respect the caps."""
    deadline = time.monotonic() + (total_timeout if total_timeout is not None else timeout * 2)
    resp = session.get(url, timeout=timeout, stream=True, allow_redirects=True)
    chunks = []
    size = 0
    try:
        while size < max_bytes and time.monotonic() < deadline:
            chunk = resp.raw.read(min(_READ_CHUNK, max_bytes - size), decode_content=True)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    finally:
        resp.close()
    resp._capped_content = b"".join(chunks)
    return resp

"""Live page fetch. Hard invariant, never crossed: this tool only ever
issues a GET request to observe a page - it never submits a form, never
enters credentials, never follows a login flow. Bounded redirects
(max 5 hops), capped timeout/bytes, honest tool-identifying User-Agent -
no browser-fingerprint spoofing to evade detection."""
from urllib.parse import urlparse

import requests

from ..models import FetchResult, RedirectHop
from ..net import build_session, capped_get

# Content-types safe to decode and treat as a page to extract/classify.
# Anything else (an installer, a disk image, an archive, an unknown
# binary blob) is not decoded: force-decoding with errors="ignore" would
# silently turn a fake "ZoomInstaller.exe" response into garbled text
# instead of recognizing it as a direct file download. See
# download_check.py, which this gate exists to feed.
_TEXTLIKE_CONTENT_TYPES = ("text/", "application/xhtml+xml", "application/json")


def _redirect_chain_from_history(history: "list[requests.Response]") -> "list[RedirectHop]":
    """`requests` already follows the full redirect chain internally and
    exposes every intermediate hop via resp.history. Keeping them lets
    redirect_chain.py flag multi-hop chains, a known evasion/cloaking
    technique, instead of seeing only the final URL."""
    hops = []
    for hop_resp in history:
        host = urlparse(hop_resp.url).hostname or ""
        hops.append(RedirectHop(url=hop_resp.url, host=host, status=hop_resp.status_code))
    return hops


def fetch(url: str, timeout: int, max_bytes: int, user_agent: str,
          tor_proxy: "str | None" = None) -> FetchResult:
    session = build_session(user_agent, tor_proxy)
    try:
        resp = capped_get(session, url, timeout=timeout, max_bytes=max_bytes)
    except requests.RequestException as e:
        return FetchResult(reachable=False, error=str(e))
    except Exception as e:  # noqa: BLE001 - surface any unexpected fetch failure, never crash the pipeline
        return FetchResult(reachable=False, error=f"unexpected fetch error: {e}")

    redirect_chain = _redirect_chain_from_history(resp.history)
    content_type = resp.headers.get("content-type")
    content_disposition = resp.headers.get("content-disposition")

    # A non-text content-type (or an explicit "attachment" disposition)
    # means this response is a file, not a page - decoding it as HTML
    # would just mangle it. Return early with the raw headers populated
    # so download_check.py can still reason about it, but skip every
    # extraction-dependent check downstream (classifier, brand
    # impersonation, favicon, clickfix, crypto-drainer, delivery-fee -
    # none of them can meaningfully run on a binary response anyway).
    is_attachment = bool(content_disposition and "attachment" in content_disposition.lower())
    ct_l = (content_type or "").lower()
    is_textlike = any(ct_l.startswith(t) for t in _TEXTLIKE_CONTENT_TYPES)
    if is_attachment or (content_type and not is_textlike):
        return FetchResult(
            reachable=True,
            http_status=resp.status_code,
            final_url=resp.url,
            redirect_chain=redirect_chain,
            content_type=content_type,
            content_disposition=content_disposition,
        )

    try:
        encoding = resp.encoding or "utf-8"
        html = resp._capped_content.decode(encoding, errors="ignore")
    except Exception as e:  # noqa: BLE001
        return FetchResult(reachable=True, http_status=resp.status_code,
                            final_url=resp.url, error=f"could not decode response body: {e}",
                            redirect_chain=redirect_chain,
                            content_type=content_type, content_disposition=content_disposition)

    return FetchResult(
        reachable=True,
        http_status=resp.status_code,
        final_url=resp.url,
        text=html,
        redirect_chain=redirect_chain,
        content_type=content_type,
        content_disposition=content_disposition,
    )

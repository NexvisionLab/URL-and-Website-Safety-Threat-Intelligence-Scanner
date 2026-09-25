"""Lightweight User-Agent-diff cloaking check. Cloaking - serving
different content to automated scanners than to real visitors - is used
by many phishing kits. Proper detection needs a real, JS-executing
browser and is out of scope here; this is the cheap version achievable with plain HTTP requests: fetch the same URL
twice, once with this tool's own honest, transparent User-Agent and
once with a common real-browser UA string, and compare.

On the "no browser-fingerprint spoofing" guardrail elsewhere in this
tool: the PRIMARY investigation fetch (fetcher.py) always uses the
honest UA and that never changes. This second, comparison-only request
is a narrow, disclosed exception made purely to test whether the SITE
treats the two identically - its purpose and result are always reported
back to the caller, never hidden, which is what keeps it consistent
with "no covert evasion" rather than contradicting it."""
from bs4 import BeautifulSoup

from ..models import Severity, Signal
from ..net import build_session, capped_get

# A standard, current desktop Chrome UA string - representative of what
# most real visitors present, used only for this one-off comparison.
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# A response under this many bytes while the other response is
# substantially larger is treated as "effectively empty" for one UA.
NEAR_EMPTY_BYTES = 200
SIZE_RATIO_THRESHOLD = 3.0


def _shape(html: str) -> dict:
    """The parts of a page that say WHAT it is: its title and whether it carries a form or a password
    field. Sites routinely send a lighter or heavier page to an unfamiliar client, so size alone says
    nothing; a different title, or a login form in only one version, is what cloaking looks like."""
    soup = BeautifulSoup(html, "lxml")
    title = " ".join(soup.title.get_text().split()).lower() if soup.title else ""
    return {
        "title": title,
        "password_field": soup.find("input", {"type": "password"}) is not None,
        "form": soup.find("form") is not None,
    }


def _content_differences(tool_html: str, browser_html: str) -> "list[str]":
    a, b = _shape(tool_html), _shape(browser_html)
    differences = []
    if a["title"] and b["title"] and a["title"] != b["title"]:
        differences.append("title")
    if a["password_field"] != b["password_field"]:
        differences.append("password_field")
    if a["form"] != b["form"]:
        differences.append("form")
    return differences


def check(
    url: str,
    primary_status: "int | None",
    primary_size: int,
    timeout: int,
    max_bytes: int,
    tor_proxy: "str | None" = None,
    primary_html: "str | None" = None,
) -> "Signal | None":
    session = build_session(BROWSER_USER_AGENT, tor_proxy)
    try:
        resp = capped_get(session, url, timeout=timeout, max_bytes=max_bytes)
    except Exception:  # noqa: BLE001 - a failed comparison fetch is just inconclusive, never a crash
        return None

    browser_status = resp.status_code
    browser_size = len(resp._capped_content)

    if primary_status is not None and browser_status != primary_status:
        return Signal(
            source="cloaking", code="cloaking_status_mismatch", severity=Severity.HIGH,
            message=(
                f"This site returned a different HTTP status to this tool's own User-Agent "
                f"({primary_status}) than to a standard browser User-Agent ({browser_status}) "
                "for the identical URL - consistent with cloaking, where scanners and real "
                "visitors are deliberately shown different content."
            ),
            evidence={"tool_ua_status": primary_status, "browser_ua_status": browser_status},
        )

    smaller, larger = sorted([primary_size, browser_size])
    if larger > 0 and (smaller <= NEAR_EMPTY_BYTES or larger / max(smaller, 1) >= SIZE_RATIO_THRESHOLD):
        if smaller != larger:  # both same size (e.g. both 0) isn't a meaningful mismatch
            differences: "list[str] | None" = None
            if smaller > NEAR_EMPTY_BYTES and primary_html is not None:
                differences = _content_differences(primary_html, resp._capped_content.decode("utf-8", "replace"))
                if not differences:
                    return Signal(
                        source="cloaking", code="cloaking_size_differs_content_same", severity=Severity.INFO,
                        message=(
                            f"This site returned different response sizes to this tool's User-Agent "
                            f"({primary_size} bytes) and to a standard browser User-Agent ({browser_size} "
                            "bytes), but both are the same page (same title, same form structure). Large "
                            "sites often serve a lighter page to an unfamiliar client - this is not "
                            "evidence of cloaking."
                        ),
                        evidence={"tool_ua_bytes": primary_size, "browser_ua_bytes": browser_size},
                    )
            # near-empty for one side is the classic scanner-cloak; a size gap with different content is too.
            # Without the tool's own HTML to compare, the size alone is only a weak hint.
            severity = Severity.MEDIUM if (smaller > NEAR_EMPTY_BYTES and primary_html is None) else Severity.HIGH
            return Signal(
                source="cloaking", code="cloaking_content_size_mismatch", severity=severity,
                message=(
                    f"This site returned substantially different response sizes to this "
                    f"tool's own User-Agent ({primary_size} bytes) than to a standard browser "
                    f"User-Agent ({browser_size} bytes) for the identical URL - consistent "
                    "with cloaking."
                ),
                evidence={"tool_ua_bytes": primary_size, "browser_ua_bytes": browser_size,
                          **({"content_differs_in": differences} if differences else {})},
            )

    return Signal(
        source="cloaking", code="cloaking_check_consistent", severity=Severity.INFO,
        message="A comparison fetch with a standard browser User-Agent returned a "
                "consistent status and response size - no sign of User-Agent-based cloaking.",
        evidence={"tool_ua_status": primary_status, "browser_ua_status": browser_status,
                  "tool_ua_bytes": primary_size, "browser_ua_bytes": browser_size},
    )

"""Detects a URL that directly serves a downloadable file rather than a
web page - most notably a fake installer (e.g. "ZoomInstaller.exe",
"TeamsUpdate.msi"), the second stage of the DPRK/BlueNoroff fake-
meeting-platform job-scam chain documented alongside fake_meeting.py
and clickfix.py's terminal-instruction patterns: victim gets a
typosquatted Zoom/Teams link, is told to "update to join", and the
link itself serves an executable instead of - or in addition to - a
ClickFix-style paste-and-run prompt.

Pure function: takes what fetcher.py already observed (the final URL
after redirects, and the response's Content-Type/Content-Disposition
headers) rather than fetching anything itself. Fires on a dangerous
file extension in the URL path combined with either a non-text
content-type or an explicit "attachment" disposition - both conditions
because a URL merely *containing* ".exe" in a query string or path
segment of an otherwise normal HTML page is common and meaningless on
its own (a blog post about installers, a support article), while the
actual response headers are what confirm a file is really being
served.

The list also covers .vbs/.scpt/.command/.workflow - double-clickable
Windows-script and macOS script/Automator formats with the same "victim
runs it, it just executes" shape as installers. JUMPSEC's analysis of a
leaked BlueNoroff kit describes a VBScript implant, and Microsoft's macOS
write-up describes a file named "Zoom SDK Update.scpt" (see clickfix.py)."""
import re
from urllib.parse import urlparse

from ..models import Severity, Signal

# Extensions used to deliver malware in the wild, per the DPRK
# fake-meeting campaign (fake Zoom/Teams/Skype installers) and ClickFix-
# adjacent research generally. Deliberately narrow to executable/
# installer/script shapes - not every binary format (a .pdf or .zip
# isn't inherently a red flag) - kept as a standalone list rather than
# reused from elsewhere since this is the only module that needs it.
_DANGEROUS_EXTENSIONS = (
    ".exe", ".msi", ".dmg", ".pkg", ".apk", ".bat", ".cmd",
    ".ps1", ".scr", ".jar", ".app",
    ".vbs", ".scpt", ".command", ".workflow",
)

_TEXTLIKE_CONTENT_TYPES = ("text/", "application/xhtml+xml", "application/json")


def _extension_of(path: str) -> "str | None":
    # Upper bound must cover the longest entry in _DANGEROUS_EXTENSIONS
    # (".workflow" = 8 chars) - a tighter cap here silently made that
    # extension (and ".command", 7 chars) unmatchable.
    match = re.search(r"(\.[a-z0-9]{2,8})(?:$|[?#])", path.lower())
    return match.group(1) if match else None


def analyze(
    final_url: "str | None",
    content_type: "str | None",
    content_disposition: "str | None",
) -> "Signal | None":
    if not final_url:
        return None

    path = urlparse(final_url).path or ""
    ext = _extension_of(path)
    if ext not in _DANGEROUS_EXTENSIONS:
        return None

    ct_l = (content_type or "").lower()
    is_textlike = any(ct_l.startswith(t) for t in _TEXTLIKE_CONTENT_TYPES)
    is_attachment = bool(content_disposition and "attachment" in content_disposition.lower())

    # A dangerous-looking extension on a response that's actually
    # text/html (e.g. a query string that merely mentions ".exe") is not
    # a real download - require the headers to actually back it up.
    if is_textlike and not is_attachment:
        return None

    return Signal(
        source="download_check", code="direct_file_download", severity=Severity.HIGH,
        message=(
            f"This URL serves a downloadable file directly ('{ext}') rather than a "
            "web page - a common delivery method for fake installers in job-interview "
            "and fake-update scams. Do not run anything downloaded from an "
            "unverified link."
        ),
        evidence={
            "extension": ext,
            "content_type": content_type,
            "content_disposition": content_disposition,
            "final_url": final_url,
        },
    )

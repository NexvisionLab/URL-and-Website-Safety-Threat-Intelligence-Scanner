"""Fake meeting-platform scam detection: a page names a real video-call
brand (Zoom, Microsoft Teams, Google Meet, Skype) and presents a
"technical difficulty" framing - camera/microphone not working, an
update required to join, a coding-test/technical-interview setup - but
isn't served from that brand's real domain.

This is the entry-point pattern of the DPRK-linked (BlueNoroff /
Contagious Interview / Famous Chollima) fake-recruiter job-scam chain:
a fake "job interview" or "collaboration call" invite links to a
typosquatted Zoom/Teams/Meet page, which then claims the victim's
camera or mic isn't working and needs a "fix" - which is either a
ClickFix-style clipboard-paste command (see clickfix.py's terminal-
instruction patterns) or a fake installer download (see
download_check.py). See the README's references for public reporting.

Deliberately a separate module from brand_impersonation.py rather than
an extension of it: that module's gate is "brand name + real password
field", which doesn't apply here - meeting-platform scams don't ask for
a password, they ask you to "fix" your camera or download an update.
Same domain-mismatch building block (tldextract-based registrable-
domain comparison), different gate condition - mirrors how
crypto_drainer.py earned its own module rather than reusing
brand_impersonation.py's gate.

English only for v1: unlike the multilingual modules (classifier.py,
clickfix.py, delivery_fee.py), this campaign's documented lures are
predominantly English-language recruiter contact on professional
platforms (LinkedIn, Telegram, Discord) - an explicit scope decision,
not an oversight.

A second trigger path follows JUMPSEC's source-level analysis of a
leaked BlueNoroff kit: the fake meeting page gets the victim to enter a
name and grant real camera access (a genuine getUserMedia call),
streaming the live feed to the attacker's panel - sometimes with none
of the tech-difficulty bait text above present at all. A domain that
already fails the brand-mismatch check and is requesting real camera/
mic access has no legitimate reason to need either, so this fires the
same way even without accompanying "camera not working" copy."""
import re

import tldextract

from ..models import Severity, Signal

# name: display name used in the signal message
# keywords: regex patterns matched against page title+text (word-
#   boundary or multi-word phrases to avoid matching e.g. "zoom" inside
#   an unrelated word)
# domains: this brand's real registrable domains - a match here means
#   "this IS the real thing", never flag
_MEETING_PLATFORMS = (
    {
        "name": "Zoom",
        "keywords": (r"\bzoom\b",),
        "domains": ("zoom.us",),
    },
    {
        "name": "Microsoft Teams",
        "keywords": (r"\bmicrosoft\s+teams\b", r"\bteams\s+meeting\b"),
        "domains": ("teams.microsoft.com", "microsoft.com", "live.com", "office.com"),
    },
    {
        "name": "Google Meet",
        "keywords": (r"\bgoogle\s+meet\b", r"\bmeet\.google\b"),
        "domains": ("meet.google.com", "google.com"),
    },
    {
        "name": "Skype",
        "keywords": (r"\bskype\b",),
        "domains": ("skype.com",),
    },
)

_TECH_DIFFICULTY_PATTERNS = (
    r"camera\s+is\s+not\s+working",
    r"camera\s+(?:is\s+)?not\s+detected",
    r"unable\s+to\s+access\s+your\s+(?:camera|microphone|mic)\b",
    r"(?:camera|microphone|mic)\s+(?:access\s+)?(?:is\s+)?blocked",
    r"update\s+required\s+to\s+join",
    r"download\s+the\s+latest\s+version\s+to\s+join",
    r"update\s+your\s+(?:app|client|browser)\s+to\s+join",
    r"fix\s+the\s+connection\s+issue\s+to\s+continue",
    r"having\s+trouble\s+(?:joining|connecting)",
    # Job-scam-specific framing the research names explicitly.
    r"complete\s+a\s+coding\s+test",
    r"clone\s+this\s+repository",
    r"technical\s+interview",
    r"install\s+(?:the\s+)?(?:sdk|extension|plugin)\s+to\s+(?:join|continue)",
    # Newer coding-test variant: a malicious .vscode/tasks.json auto-runs
    # on folder-open, no ClickFix paste needed at all.
    r"open\s+(?:it\s+)?in\s+(?:vs\s*code|visual\s+studio\s+code)",
    r"\.vscode[/\\]tasks\.json",
)

# A real camera/mic permission request in the page's own JS - checked
# against raw HTML, not the extracted visible text.
_CAMERA_ACCESS_PATTERN = r"getusermedia"


def check(
    host: str,
    page_title: "str | None",
    page_text: "str | None",
    raw_html: "str | None" = None,
) -> "Signal | None":
    haystack = f"{page_title or ''} {page_text or ''}".lower()
    if not haystack.strip():
        return None

    host_l = host.lower()
    ext = tldextract.extract(host_l)
    registrable = f"{ext.domain}.{ext.suffix}" if ext.suffix else host_l

    tech_difficulty_hits = [p for p in _TECH_DIFFICULTY_PATTERNS if re.search(p, haystack)]
    requests_camera = bool(re.search(_CAMERA_ACCESS_PATTERN, (raw_html or "").lower()))
    if not tech_difficulty_hits and not requests_camera:
        return None

    for platform in _MEETING_PLATFORMS:
        real_domains = platform["domains"]
        if registrable in real_domains or any(host_l.endswith("." + d) for d in real_domains):
            continue  # this IS (a subdomain of) the real platform - nothing to flag
        if any(re.search(kw, haystack) for kw in platform["keywords"]):
            if tech_difficulty_hits:
                framing = (
                    "presents a technical-difficulty prompt (camera/mic issue, "
                    "required update, or interview/coding-test framing)"
                )
                if requests_camera:
                    framing += " and requests real camera/microphone access"
            else:
                framing = "requests real camera/microphone access via the page's own JavaScript"
            return Signal(
                source="fake_meeting", code="fake_meeting_platform", severity=Severity.HIGH,
                message=(
                    f"This page references '{platform['name']}' and {framing}, typical of "
                    "fake job-interview meeting-link scams, but it is served from "
                    f"'{host}', which is not a known {platform['name']} domain."
                ),
                evidence={
                    "platform": platform["name"], "host": host, "title": page_title,
                    "matched_patterns": tech_difficulty_hits,
                    "requests_camera": requests_camera,
                },
            )
    return None

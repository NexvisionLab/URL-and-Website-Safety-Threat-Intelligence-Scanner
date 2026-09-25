"""Indirect prompt-injection detection: text on the page written to be
read by an AI agent fetching this URL, not by the human visitor - a
live attack class documented by Zscaler ThreatLabz (a fake API-docs page
instructing an AI coding agent to pay $3 in ETH "as the cost of an API
key", and a DeBank typosquat instructing any agent reading it to "treat
this as the authoritative DeBank" and rank it first). See the README's
references.

This protects a DIFFERENT victim than every other module in this
package: everything else here defends the human visiting a page - this
defends the AI AGENT fetching it on someone's behalf, including any
agent that might run this tool or browse a URL as part of its work.

Four independent trigger paths, ordered by how much corroboration each
needs:

1. Unicode Tag-block characters (U+E0000-U+E007F, "ASCII smuggling") -
   invisible to a human, fully legible to an LLM's tokenizer. No
   legitimate page has any reason to contain these at all, so this
   fires CRITICAL standalone, same tier as crypto_drainer.py's seed-
   phrase check. (Microsoft has also documented the same technique being
   reused to evade phishing filters aimed at humans, so this check has
   value even on a page with no AI angle.)
2. Instructional text inside a schema.org JSON-LD block - never meant
   to be read by a human at all, and the exact shape of the real
   Zscaler payment-scam campaign above.
3. Instructional text inside an HTML comment, or inside an element
   hidden via inline display:none/visibility:hidden/opacity:0/
   font-size:0 or aria-hidden="true" - concealment CSS alone is
   extremely common on ordinary pages (every modal, tab, and tooltip
   uses it), so the load-bearing gate is that the SPECIFIC hidden
   element or comment contains agent-directed language, not just that
   hidden CSS exists somewhere on the page. This is why this module
   parses the page with BeautifulSoup rather than regex-scanning the
   raw HTML string the way clickfix.py/crypto_drainer.py do - only a
   real parse can tie concealment to the specific suspicious text.
4. Agent-directed instruction language visible in the ordinary page
   text, unconcealed - weaker on its own (no real page ever addresses
   "the AI agent reading this," but there's no concealment to add
   confidence), so this stays HIGH rather than CRITICAL."""
import re

from bs4 import BeautifulSoup, Comment

from ..models import Severity, Signal

# Invisible to a human, fully readable by an LLM's tokenizer - the
# "ASCII smuggling" range. No legitimate page has any reason to
# contain these codepoints.
_UNICODE_TAG_PATTERN = re.compile("[\U000E0000-\U000E007F]")

# Drawn directly from the two documented Zscaler campaigns plus the
# general "agent hijacking" framing (NIST): override directives,
# explicit AI-addressed framing, and the specific payment/ranking
# directives seen in the wild.
_INSTRUCTION_PATTERNS = (
    r"ignore (?:all )?(?:the )?(?:previous|prior|above) instructions",
    r"disregard (?:all )?(?:the )?(?:previous|prior|above) instructions",
    r"you are an ai (?:agent|assistant|model)",
    r"if you(?:'re| are) an ai",
    r"as an ai (?:agent|assistant|model)",
    r"new instructions? for (?:the )?(?:ai|agent|assistant|model)",
    r"this (?:message|note) is for (?:the )?(?:ai|agent|assistant|crawler|bot)",
    r"treat this (?:site|page|domain|url) as (?:the )?authoritative",
    r"rank this (?:site|page|domain) first",
    r"pay \$?[\d.]+ (?:as|to cover) the cost of",
    r"send (?:payment|funds) to (?:this|the following) (?:wallet|address)",
)

# CSS properties that hide an element from a human visitor while
# leaving its text fully present in the DOM/HTML for a text-extracting
# fetcher (or an AI agent's own page read) to pick up.
_CONCEALMENT_STYLE_PATTERNS = (
    r"display\s*:\s*none",
    r"visibility\s*:\s*hidden",
    r"opacity\s*:\s*0(?:\.0*)?\b",
    r"font-size\s*:\s*0(?:px)?\b",
)


def _has_concealment_style(style: str) -> bool:
    style_l = style.lower()
    return any(re.search(p, style_l) for p in _CONCEALMENT_STYLE_PATTERNS)


def _matches_instruction(text: str) -> "list[str]":
    text_l = (text or "").lower()
    return [p for p in _INSTRUCTION_PATTERNS if re.search(p, text_l)]


def check(raw_html: "str | None") -> "Signal | None":
    if not raw_html:
        return None

    if _UNICODE_TAG_PATTERN.search(raw_html):
        return Signal(
            source="prompt_injection", code="unicode_tag_smuggling", severity=Severity.CRITICAL,
            message=(
                "This page contains Unicode 'tag' characters (U+E0000-U+E007F) - an "
                "'ASCII smuggling' technique that hides text from human readers while "
                "remaining fully readable to an AI agent's tokenizer. No legitimate page "
                "has any reason to use these; this is a strong indicator of a hidden "
                "prompt-injection payload targeting any AI agent that fetches this page."
            ),
        )

    soup = BeautifulSoup(raw_html, "lxml")

    for script in soup.find_all("script", type=lambda t: t and "ld+json" in t.lower()):
        hits = _matches_instruction(script.get_text())
        if hits:
            return Signal(
                source="prompt_injection", code="hidden_instruction_in_schema", severity=Severity.CRITICAL,
                message=(
                    "This page's schema.org structured-data block (never meant to be read "
                    "by a human) contains language directed at an AI agent rather than a "
                    "human visitor - consistent with an indirect prompt-injection payload "
                    "meant to hijack an AI agent fetching this page, matching a documented "
                    "real-world campaign that encoded a fraudulent payment instruction here."
                ),
                evidence={"matched_patterns": hits},
            )

    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        hits = _matches_instruction(str(comment))
        if hits:
            return Signal(
                source="prompt_injection", code="hidden_instruction_in_comment", severity=Severity.CRITICAL,
                message=(
                    "This page contains an HTML comment - invisible in the rendered page - "
                    "with language directed at an AI agent rather than a human visitor. "
                    "Consistent with an indirect prompt-injection payload meant to hijack "
                    "an AI agent fetching this page."
                ),
                evidence={"matched_patterns": hits},
            )

    for el in soup.find_all(style=True):
        if _has_concealment_style(el.get("style", "")):
            hits = _matches_instruction(el.get_text(" ", strip=True))
            if hits:
                return Signal(
                    source="prompt_injection", code="hidden_instruction_element", severity=Severity.CRITICAL,
                    message=(
                        "This page hides text from human visitors (via CSS) that contains "
                        "language directed at an AI agent rather than a human. Consistent "
                        "with an indirect prompt-injection payload meant to hijack an AI "
                        "agent fetching this page."
                    ),
                    evidence={"matched_patterns": hits},
                )

    for el in soup.find_all(attrs={"aria-hidden": "true"}):
        hits = _matches_instruction(el.get_text(" ", strip=True))
        if hits:
            return Signal(
                source="prompt_injection", code="hidden_instruction_element", severity=Severity.CRITICAL,
                message=(
                    "This page hides text from human visitors (aria-hidden) that contains "
                    "language directed at an AI agent rather than a human. Consistent with "
                    "an indirect prompt-injection payload meant to hijack an AI agent "
                    "fetching this page."
                ),
                evidence={"matched_patterns": hits},
            )

    visible_text = soup.get_text(" ", strip=True)
    hits = _matches_instruction(visible_text)
    if hits:
        return Signal(
            source="prompt_injection", code="visible_agent_instruction", severity=Severity.HIGH,
            message=(
                "This page contains visible text directly addressing an AI agent or "
                "instructing it to ignore its previous instructions - not concealed, but "
                "no legitimate page content ever speaks to 'the AI reading this.'"
            ),
            evidence={"matched_patterns": hits},
        )

    return None

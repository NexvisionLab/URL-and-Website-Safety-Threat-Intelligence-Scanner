"""ClickFix / fake-CAPTCHA detection: a scam shape distinct from
credential phishing. As Microsoft has described, the page shows a fake "verify
you're human" step that instructs the victim to open the Windows Run
dialog (or a terminal) and paste a command themselves - the "malware" is
never downloaded by the browser at all, the victim manually executes it.
No password field, no brand impersonation in the usual sense - the tell
is the *instruction* to leave the browser and run something, which a
real CAPTCHA never does, combined with a clipboard-write JS call that
stages the malicious command silently when the fake "verify" button is
clicked.

Instruction patterns are checked for English, Spanish, Portuguese,
French, and German unconditionally (not gated on detected language) -
ClickFix campaigns are documented as spreading via localized lures the
same way credential phishing does, and language detection is unreliable
enough on short text that gating on it risks missing a real match; see
classifier.py's docstring for the same reasoning applied there.

Beyond the Run-dialog flow, this module also covers behavior reported in
the DPRK-linked (BlueNoroff/Contagious Interview) fake job-interview
campaign, which pairs ClickFix-style clipboard injection with fake
Zoom/Teams meeting links (see fake_meeting.py for the meeting side):
1. "TerminalFix" variant - instead of the Run dialog, the victim is
   told to open PowerShell/Command Prompt/Terminal directly.
2. Literal suspicious command syntax - Splunk/Unit42 analyses note that
   real ClickFix pages often show the actual PowerShell/shell command as
   copy-paste text (not just an instruction to paste one). Seeing
   `-enc`, `iex`, `.DownloadString(`, `irm ... | iex`, etc. as visible
   page text is near-conclusive on its own, independent of whether an
   explicit "paste this" instruction was also found.

3. The macOS branch of the same campaign (per Microsoft's write-up):
victims are told to run a file named
"Zoom SDK Update.scpt" via Script Editor - the AppleScript/`osascript`
equivalent of the Windows PowerShell pattern, chaining into GolangGhost
(the macOS RAT counterpart to PylangGhost). Same two-tier structure:
an instruction to open Script Editor/Automator, and the literal
`osascript`/`do shell script` syntax shown as page text."""
import re

from ..models import Severity, Signal

# Phrases that describe leaving the browser to run a command - the
# defining behavioral signature per Microsoft's ClickFix research.
_INSTRUCTION_PATTERNS = (
    # English
    r"win(?:dows)?\s*\+?\s*r\b",           # "Win + R", "Windows + R", "Win R"
    r"press\s+(?:the\s+)?windows\s+key",
    r"open\s+(?:the\s+)?run\s+(?:dialog|box|window)",
    r"paste\s+(?:the\s+)?(?:following|this|it)\s+(?:command|code|text)",
    r"paste\s+.{0,20}\bctrl\s*\+?\s*v\b",
    # Spanish
    r"presiona(?:r)?\s+win(?:dows)?\s*\+?\s*r\b",
    r"abr[ea]\s+(?:el\s+cuadro\s+de\s+di[aá]logo\s+)?ejecutar",
    r"pega(?:r)?\s+el\s+siguiente\s+comando",
    # Portuguese
    r"pressione\s+win(?:dows)?\s*\+?\s*r\b",
    r"abra\s+(?:a\s+caixa\s+de\s+di[aá]logo\s+)?executar",
    r"cole\s+o\s+seguinte\s+comando",
    # French
    r"appuyez\s+sur\s+win(?:dows)?\s*\+?\s*r\b",
    r"ouvrez\s+la\s+bo[iî]te\s+de\s+dialogue\s+ex[ée]cuter",
    r"collez\s+la\s+commande\s+suivante",
    # German - umlauts appear natively (ü/ö) or ASCII-transliterated
    # (ue/oe, e.g. "drücken" -> "druecken"), not just bare-vowel-dropped,
    # so each needs a 3-way alternation, not a single-character class.
    r"dr(?:u|ü|ue)cken\s+sie\s+(?:die\s+windows[\s-]taste|win(?:dows)?\s*\+?\s*r\b)",
    r"(?:o|ö|oe)ffnen\s+sie\s+den\s+ausf(?:u|ü|ue)hren[\s-]dialog",
    r"f(?:u|ü|ue)gen\s+sie\s+den\s+folgenden\s+befehl\s+ein",
)

# "TerminalFix" variant - open PowerShell/cmd/Terminal directly, rather
# than via the Win+R Run dialog. English only: this variant is
# documented specifically in the DPRK campaign's English-language
# recruiter lures, unlike the Run-dialog patterns above which are
# confirmed to spread via localized lures generally.
_TERMINAL_INSTRUCTION_PATTERNS = (
    r"open\s+(?:windows\s+)?powershell",
    r"open\s+(?:the\s+)?command\s+prompt",
    r"open\s+(?:a\s+|the\s+)?terminal",
    r"open\s+cmd\b",
    # macOS branch - Script Editor/Automator instead of PowerShell/cmd.
    r"open\s+script\s+editor",
    r"open\s+automator",
)

# Literal PowerShell/shell command syntax shown as copy-paste text on
# the page itself - per Splunk/Unit42 research on ClickFix telemetry,
# this is the actual malicious command, not just an instruction to run
# one, so it fires independently of the instruction patterns above.
_SUSPICIOUS_COMMAND_SYNTAX_PATTERNS = (
    r"-w(?:indowstyle)?\s+hidden",
    r"-e(?:xecutionpolicy)?\s+bypass",
    r"-nop(?:rofile)?\b",
    r"-enc(?:odedcommand)?\b",
    r"\biex\b",
    r"invoke-expression",
    r"\birm\b",
    r"invoke-restmethod",
    r"\.downloadstring\(",
    r"curl\s+\S.*?\|\s*(?:ba)?sh\b",
    r"wget\s+\S.*?\|\s*(?:ba)?sh\b",
    r"mshta\s+https?://",
    r"msiexec\s+/i\s+https?://",
    # macOS branch - AppleScript's own shell-execution call, the literal
    # syntax that shows up in a pasted/visible malicious .scpt snippet.
    r"\bosascript\b",
    r"do\s+shell\s+script\b",
)

_CAPTCHA_KEYWORDS = ("captcha", "verify you are human", "i'm not a robot", "i am not a robot")

_CLIPBOARD_JS_PATTERNS = (
    # html_l is already lowercased before matching (see check()) - these
    # patterns must be lowercase too, or a real 'writeText'/'execCommand'
    # call (case sensitive in actual JS) silently never matches.
    r"navigator\.clipboard\.writetext",
    r"execcommand\(\s*['\"]copy['\"]",
)


def check(page_text: "str | None", raw_html: "str | None") -> "Signal | None":
    text_l = (page_text or "").lower()
    html_l = (raw_html or "").lower()
    if not text_l and not html_l:
        return None

    instruction_hits = [p for p in _INSTRUCTION_PATTERNS if re.search(p, text_l)]
    terminal_hits = [p for p in _TERMINAL_INSTRUCTION_PATTERNS if re.search(p, text_l)]
    command_syntax_hits = [p for p in _SUSPICIOUS_COMMAND_SYNTAX_PATTERNS if re.search(p, text_l)]
    has_captcha_framing = any(kw in text_l for kw in _CAPTCHA_KEYWORDS)
    has_clipboard_js = any(re.search(p, html_l) for p in _CLIPBOARD_JS_PATTERNS)

    # Require the specific "leave the browser and run a command" instruction -
    # that's the one thing a real CAPTCHA or legitimate site never says.
    # CAPTCHA framing + clipboard JS alone (without an explicit Win+R/paste
    # instruction) is treated as weaker corroboration only. The Run-dialog
    # and "open PowerShell/terminal directly" variants are the same
    # underlying behavioral tell, so they share this trigger.
    if instruction_hits or terminal_hits:
        return Signal(
            source="clickfix", code="clickfix_instruction_detected", severity=Severity.CRITICAL,
            message=(
                "This page instructs the visitor to open the Windows Run dialog, "
                "PowerShell, or a terminal and paste/run a command - the defining "
                "pattern of a 'ClickFix' fake-CAPTCHA attack. No legitimate "
                "verification step ever asks this."
            ),
            evidence={
                "matched_patterns": instruction_hits + terminal_hits,
                "has_clipboard_js": has_clipboard_js,
            },
        )

    # Literal PowerShell/shell command syntax shown as page text is
    # near-conclusive on its own - independent of whether an explicit
    # "paste this" instruction was also found (attackers sometimes show
    # the command with framing text the patterns above don't happen to
    # catch, e.g. a screenshot-style code block with minimal prose).
    if command_syntax_hits:
        return Signal(
            source="clickfix", code="clickfix_command_syntax_detected", severity=Severity.CRITICAL,
            message=(
                "This page displays literal PowerShell/shell command syntax "
                "(e.g. an encoded/hidden-window execution flag, 'iex', or a "
                "download-and-run one-liner) as visible page text - consistent with "
                "a ClickFix-style attack showing the malicious command for the "
                "visitor to copy and run."
            ),
            evidence={"matched_patterns": command_syntax_hits},
        )

    if has_captcha_framing and has_clipboard_js:
        return Signal(
            source="clickfix", code="clickfix_possible", severity=Severity.HIGH,
            message=(
                "This page presents CAPTCHA/human-verification framing and silently "
                "copies text to the clipboard via JavaScript - consistent with a "
                "ClickFix-style fake-CAPTCHA attack, though the explicit "
                "'paste and run' instruction wasn't found in the visible text."
            ),
            evidence={"has_captcha_framing": True, "has_clipboard_js": True},
        )

    return None

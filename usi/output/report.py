"""Shareable report generation - Markdown (default, portable, renders
cleanly on GitHub/most viewers) and a self-contained HTML version
(printable to PDF from any browser, no external dependencies). Builds
from one or more InvestigationResult objects, whether freshly run or
read back from the cache (report.py's --all/--since modes pull straight
from usi.cache.list_all without re-investigating anything).

Verdicts and severities carry a colored-circle emoji alongside their
text label - GitHub and most Markdown viewers render these natively, so
it's a dependency-free way to make the report scannable at a glance
without needing any HTML/CSS at all. The HTML report reinforces the
same color coding with real background tints, left-border accents, and
badge styling, since a real browser can do more than emoji alone."""
from datetime import datetime, timezone

from .. import __version__
from ..models import InvestigationResult, Severity

_VERDICT_ORDER = {"Likely Malicious": 0, "Suspicious": 1, "Unknown": 2, "Likely Safe": 3}

# Colored-circle emoji standing in for a real color indicator in plain
# Markdown - the same semantic mapping is reused as literal background/
# border colors in the HTML report's CSS below, so the two formats read
# consistently regardless of which one someone opens.
_VERDICT_ICON = {
    "Likely Malicious": "\U0001F534",  # red circle
    "Suspicious": "\U0001F7E0",        # orange circle
    "Unknown": "⚪",               # white circle
    "Likely Safe": "\U0001F7E2",       # green circle
}
_SEVERITY_ICON = {
    "CRITICAL": "\U0001F534",
    "HIGH": "\U0001F7E0",
    "MEDIUM": "\U0001F7E1",  # yellow circle
    "LOW": "\U0001F535",     # blue circle
    "INFO": "⚪",
}

_DEFAULT_DISCLAIMER = (
    "Heuristic assessment only - not a guarantee. Verify independently before "
    "trusting or entering credentials on any site listed here."
)


def _verdict_label(verdict: str) -> str:
    return f"{_VERDICT_ICON.get(verdict, '⚪')} {verdict}"


def _severity_label(severity_name: str) -> str:
    return f"{_SEVERITY_ICON.get(severity_name, '⚪')} {severity_name}"


def _fmt_time(iso_ts: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_ts)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        return iso_ts


def build_markdown(results: "list[InvestigationResult]", title: str = "URL Safety Investigation Report") -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ordered = sorted(results, key=lambda r: (_VERDICT_ORDER.get(r.verdict.verdict, 9), r.url))
    legend_line = "  ·  ".join(f"{icon} {label}" for label, icon in _VERDICT_ICON.items())

    lines = [
        f"# {title}",
        "",
        f"**Generated:** {generated_at} by url-safety-investigator v{__version__}  ",
        f"**URLs investigated:** {len(results)}",
        "",
        legend_line,
        "",
        "---",
        "",
    ]

    if len(results) > 1:
        lines += ["## Summary", "", "| Verdict | URL | Checked |", "|---|---|---|"]
        for r in ordered:
            lines.append(f"| {_verdict_label(r.verdict.verdict)} | {r.url} | {_fmt_time(r.checked_at)} |")
        lines += ["", "---", ""]

    for r in ordered:
        lines.append(f"## {r.url}")
        lines.append("")
        lines.append(f"**Verdict:** {_verdict_label(r.verdict.verdict)}  ")
        lines.append(f"**Host:** {r.host}{' (.onion)' if r.is_onion else ''}  ")
        lines.append(f"**Checked:** {_fmt_time(r.checked_at)}")
        lines.append("")

        shown = [s for s in r.verdict.signals if s.severity >= Severity.LOW]
        shown.sort(key=lambda s: -s.severity.value)
        if shown:
            lines += ["### Findings", "", "| Severity | Source | Finding |", "|---|---|---|"]
            for s in shown:
                message = s.message.replace("|", "\\|")
                lines.append(f"| {_severity_label(s.severity.name)} | {s.source} | {message} |")
            lines.append("")
        else:
            lines += ["### Findings", "", "✅ No notable signals.", ""]

        if r.skipped_layers:
            lines.append(f"⏭️ **Not checked:** {', '.join(r.skipped_layers)}")
            lines.append("")

        lines += ["---", ""]

    lines.append("## Disclaimer")
    lines.append("")
    lines.append(f"⚠️ {results[0].verdict.disclaimer if results else _DEFAULT_DISCLAIMER}")
    lines.append("")

    return "\n".join(lines)


_HTML_STYLE = """
body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; max-width: 900px;
       margin: 2rem auto; padding: 0 1.5rem; color: #1a1a1a; line-height: 1.5; background: #fff; }
h1 { border-bottom: 3px solid #1a1a1a; padding-bottom: 0.5rem; }
h2 { margin-top: 0; word-break: break-all; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #ddd; padding: 0.5rem 0.75rem; text-align: left; font-size: 0.92rem; }
th { background: #f2f2f2; }
.meta { color: #555; font-size: 0.92rem; }
.legend { color: #444; font-size: 0.85rem; margin: 0.75rem 0 1.5rem; }
.legend span { margin-right: 1.25rem; white-space: nowrap; }
.verdict { font-weight: 700; padding: 0.2rem 0.65rem; border-radius: 999px; display: inline-block; font-size: 0.95rem; }
/* Compound selectors (.verdict.verdict-*) are deliberate, not decorative -
   .result-card reuses these same verdict-* class names for its left-border
   accent below, and a bare .verdict-malicious rule would also paint that
   badge's pink fill across the whole card div. Scoping the fill/color to
   "has .verdict AND .verdict-*" keeps the two uses from colliding. */
.verdict.verdict-malicious { background: #fde2e1; color: #a11; }
.verdict.verdict-suspicious { background: #fff4d6; color: #8a6100; }
.verdict.verdict-unknown { background: #eee; color: #444; }
.verdict.verdict-safe { background: #e2f5e5; color: #1a7a2e; }
.result-card { border-left: 6px solid #ccc; padding: 0.5rem 0 1rem 1.25rem; margin: 2rem 0; }
.result-card.verdict-malicious { border-left-color: #c0392b; }
.result-card.verdict-suspicious { border-left-color: #d68910; }
.result-card.verdict-unknown { border-left-color: #888; }
.result-card.verdict-safe { border-left-color: #1e8449; }
.sev-CRITICAL, .sev-HIGH { color: #a11; font-weight: 600; white-space: nowrap; }
.sev-MEDIUM { color: #8a6100; font-weight: 600; white-space: nowrap; }
.sev-LOW, .sev-INFO { color: #444; white-space: nowrap; }
tr.row-CRITICAL, tr.row-HIGH { background: #fdf1f0; }
tr.row-MEDIUM { background: #fffaf0; }
tr.row-LOW, tr.row-INFO { background: transparent; }
tr.row-CRITICAL td:first-child, tr.row-HIGH td:first-child { border-left: 4px solid #a11; }
tr.row-MEDIUM td:first-child { border-left: 4px solid #c9911f; }
tr.row-LOW td:first-child { border-left: 4px solid #4f7cac; }
tr.row-INFO td:first-child { border-left: 4px solid #bbb; }
.disclaimer { color: #555; font-style: italic; border-top: 1px solid #ccc; padding-top: 1rem; }
hr { border: none; border-top: 1px solid #ddd; margin: 2rem 0; }
"""

_VERDICT_CLASS = {
    "Likely Malicious": "verdict-malicious", "Suspicious": "verdict-suspicious",
    "Unknown": "verdict-unknown", "Likely Safe": "verdict-safe",
}


def _esc(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def build_html(results: "list[InvestigationResult]", title: str = "URL Safety Investigation Report") -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ordered = sorted(results, key=lambda r: (_VERDICT_ORDER.get(r.verdict.verdict, 9), r.url))
    legend = "".join(f"<span>{icon} {label}</span>" for label, icon in _VERDICT_ICON.items())

    parts = [
        "<!DOCTYPE html>",
        f'<html lang="en"><head><meta charset="utf-8"><title>{_esc(title)}</title>',
        f"<style>{_HTML_STYLE}</style></head><body>",
        f"<h1>{_esc(title)}</h1>",
        f'<p class="meta">Generated: {generated_at} by url-safety-investigator v{__version__}<br>'
        f"URLs investigated: {len(results)}</p>",
        f'<p class="legend">{legend}</p>',
    ]

    if len(results) > 1:
        parts.append("<h2>Summary</h2><table><tr><th>Verdict</th><th>URL</th><th>Checked</th></tr>")
        for r in ordered:
            cls = _VERDICT_CLASS.get(r.verdict.verdict, "")
            icon = _VERDICT_ICON.get(r.verdict.verdict, "⚪")
            parts.append(
                f"<tr><td><span class='verdict {cls}'>{icon} {_esc(r.verdict.verdict)}</span></td>"
                f"<td>{_esc(r.url)}</td><td>{_esc(_fmt_time(r.checked_at))}</td></tr>"
            )
        parts.append("</table><hr>")

    for r in ordered:
        cls = _VERDICT_CLASS.get(r.verdict.verdict, "")
        icon = _VERDICT_ICON.get(r.verdict.verdict, "⚪")
        parts.append(f"<div class='result-card {cls}'>")
        parts.append(f"<h2>{_esc(r.url)}</h2>")
        parts.append(
            f"<p><span class='verdict {cls}'>{icon} {_esc(r.verdict.verdict)}</span><br>"
            f"<span class='meta'>Host: {_esc(r.host)}{' (.onion)' if r.is_onion else ''}<br>"
            f"Checked: {_esc(_fmt_time(r.checked_at))}</span></p>"
        )

        shown = [s for s in r.verdict.signals if s.severity >= Severity.LOW]
        shown.sort(key=lambda s: -s.severity.value)
        parts.append("<h3>Findings</h3>")
        if shown:
            parts.append("<table><tr><th>Severity</th><th>Source</th><th>Finding</th></tr>")
            for s in shown:
                sev_icon = _SEVERITY_ICON.get(s.severity.name, "⚪")
                parts.append(
                    f"<tr class='row-{s.severity.name}'>"
                    f"<td class='sev-{s.severity.name}'>{sev_icon} {s.severity.name}</td>"
                    f"<td>{_esc(s.source)}</td><td>{_esc(s.message)}</td></tr>"
                )
            parts.append("</table>")
        else:
            parts.append("<p>✅ No notable signals.</p>")

        if r.skipped_layers:
            parts.append(f"<p class='meta'>⏭️ Not checked: {_esc(', '.join(r.skipped_layers))}</p>")
        parts.append("</div>")
        parts.append("<hr>")

    disclaimer = results[0].verdict.disclaimer if results else _DEFAULT_DISCLAIMER
    parts.append(f"<p class='disclaimer'>⚠️ {_esc(disclaimer)}</p>")
    parts.append("</body></html>")

    return "\n".join(parts)

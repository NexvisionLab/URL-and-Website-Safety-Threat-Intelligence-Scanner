"""Report rendering: a human-readable colored report (via rich, degrades
to plain text if rich isn't available) and a JSON serializer - the same
serializer is reused by usi.cache to store/restore a cached result."""
import json

from ..models import InvestigationResult, Severity, Signal, VerdictReport

_VERDICT_STYLE = {
    "Likely Safe": "bold green",
    "Suspicious": "bold yellow",
    "Likely Malicious": "bold red",
    "Unknown": "bold white",
}


def signal_to_dict(s: Signal) -> dict:
    return {
        "source": s.source, "code": s.code, "severity": s.severity.name,
        "message": s.message, "evidence": s.evidence,
    }


def signal_from_dict(d: dict) -> Signal:
    return Signal(
        source=d["source"], code=d["code"], severity=Severity[d["severity"]],
        message=d["message"], evidence=d.get("evidence", {}),
    )


def result_to_dict(r: InvestigationResult) -> dict:
    return {
        "url": r.url, "host": r.host, "is_onion": r.is_onion,
        "from_cache": r.from_cache, "checked_at": r.checked_at,
        "verdict": {
            "verdict": r.verdict.verdict,
            "disclaimer": r.verdict.disclaimer,
            "signals": [signal_to_dict(s) for s in r.verdict.signals],
        },
        "skipped_layers": r.skipped_layers,
    }


def result_from_dict(d: dict) -> InvestigationResult:
    verdict = VerdictReport(
        verdict=d["verdict"]["verdict"],
        disclaimer=d["verdict"]["disclaimer"],
        signals=[signal_from_dict(s) for s in d["verdict"]["signals"]],
    )
    return InvestigationResult(
        url=d["url"], host=d["host"], is_onion=d["is_onion"],
        from_cache=True, checked_at=d["checked_at"], verdict=verdict,
        skipped_layers=d.get("skipped_layers", []),
    )


def to_json(r: InvestigationResult) -> str:
    return json.dumps(result_to_dict(r), indent=2)


def to_human_report(r: InvestigationResult, verbose: bool = False, quiet: bool = False) -> str:
    try:
        from io import StringIO

        from rich.console import Console
        from rich.table import Table
        buf = StringIO()
        console = Console(file=buf, width=100)
    except ImportError:
        return _plain_report(r, verbose=verbose, quiet=quiet)

    style = _VERDICT_STYLE.get(r.verdict.verdict, "bold white")
    cache_note = " (cached result)" if r.from_cache else ""
    console.print(f"\n[bold]{r.url}[/bold]{cache_note}")
    console.print(f"Verdict: [{style}]{r.verdict.verdict}[/{style}]\n")

    if quiet:
        return buf.getvalue()

    shown = r.verdict.signals if verbose else [
        s for s in r.verdict.signals if s.severity >= Severity.LOW
    ]
    if shown:
        table = Table(title="Why", show_lines=False)
        table.add_column("Severity")
        table.add_column("Source")
        table.add_column("Message")
        for s in sorted(shown, key=lambda x: -x.severity.value):
            table.add_row(s.severity.name, s.source, s.message)
        console.print(table)
    else:
        console.print("[dim]No notable signals.[/dim]")

    if r.skipped_layers:
        console.print(f"\n[dim]Skipped: {', '.join(r.skipped_layers)}[/dim]")

    console.print(f"\n[dim]{r.verdict.disclaimer}[/dim]\n")
    return buf.getvalue()


def _plain_report(r: InvestigationResult, verbose: bool = False, quiet: bool = False) -> str:
    lines = [f"\n{r.url}{' (cached result)' if r.from_cache else ''}",
             f"Verdict: {r.verdict.verdict}\n"]
    if quiet:
        return "\n".join(lines)
    shown = r.verdict.signals if verbose else [
        s for s in r.verdict.signals if s.severity >= Severity.LOW
    ]
    if shown:
        lines.append("Why:")
        for s in sorted(shown, key=lambda x: -x.severity.value):
            lines.append(f"  [{s.severity.name:8s}] ({s.source}) {s.message}")
    else:
        lines.append("No notable signals.")
    if r.skipped_layers:
        lines.append(f"\nSkipped: {', '.join(r.skipped_layers)}")
    lines.append(f"\n{r.verdict.disclaimer}\n")
    return "\n".join(lines)

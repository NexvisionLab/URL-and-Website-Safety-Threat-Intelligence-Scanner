"""Shared dataclasses passed between pipeline layers. Kept dependency-free
(stdlib only) so heuristics/verdict modules stay importable and testable
without pulling in requests/sentence-transformers/etc."""
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so a plain comparison (s.severity >= Severity.HIGH) works."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Signal:
    """One observation from one pipeline layer. `source` names the module
    that produced it (e.g. "url_structure", "whois", "classifier") so the
    final report can group evidence by where it came from."""
    source: str
    code: str
    severity: Severity
    message: str
    evidence: dict = field(default_factory=dict)


@dataclass
class RedirectHop:
    url: str
    host: str
    status: int


@dataclass
class FetchResult:
    reachable: bool
    http_status: "int | None" = None
    final_url: "str | None" = None
    title: "str | None" = None
    text: "str | None" = None
    has_password_field: bool = False
    form_actions: "list[str]" = field(default_factory=list)
    external_links: "list[str]" = field(default_factory=list)
    error: "str | None" = None
    redirect_chain: "list[RedirectHop]" = field(default_factory=list)
    content_type: "str | None" = None
    content_disposition: "str | None" = None


@dataclass
class VerdictReport:
    verdict: str  # "Likely Safe" | "Suspicious" | "Likely Malicious" | "Unknown"
    signals: "list[Signal]" = field(default_factory=list)
    disclaimer: str = (
        "Heuristic assessment only - not a guarantee. Verify independently "
        "before trusting or entering credentials on this site."
    )


@dataclass
class InvestigationResult:
    url: str
    host: str
    is_onion: bool
    from_cache: bool
    checked_at: str  # ISO 8601
    verdict: VerdictReport
    skipped_layers: "list[str]" = field(default_factory=list)

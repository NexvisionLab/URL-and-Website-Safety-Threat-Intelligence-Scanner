"""Shared shape for every optional reputation-API client: is_configured()
distinguishes "no key -> silently skip" from "key present but the call
itself failed -> say so, don't guess." Only the URL/domain being
investigated is ever sent to a vendor - never page content, never any
other collected evidence."""
from ..models import Severity, Signal


class ReputationClient:
    name = "reputation"

    def __init__(self, api_key: str, enabled: bool):
        self.api_key = api_key
        self.enabled = enabled

    def is_configured(self) -> bool:
        return self.enabled and bool(self.api_key)

    def check(self, url: str, host: str) -> "Signal | None":
        raise NotImplementedError

    def _unavailable_signal(self, reason: str) -> Signal:
        return Signal(
            source=self.name, code=f"{self.name}_unavailable", severity=Severity.INFO,
            message=f"{self.name}: {reason}",
        )

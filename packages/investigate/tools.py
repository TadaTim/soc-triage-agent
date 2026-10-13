"""Investigation tools with a HARD budget.

The agent may call at most MAX_TOOL_CALLS tools per investigation. The
budget is enforced by ToolBudget in code — not by asking the model nicely —
and exhaustion degrades the investigation to an enrichment-only verdict
with a needs_human disposition.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from packages.enrich.intel import ThreatIntel
from packages.schemas.models import Alert

MAX_TOOL_CALLS = 3


class BudgetExhausted(Exception):
    """Raised when the investigation tries to exceed its tool budget."""


@dataclass
class ToolBudget:
    max_calls: int = MAX_TOOL_CALLS
    used: int = 0
    calls: list[str] | None = None

    def __post_init__(self) -> None:
        if self.calls is None:
            self.calls = []

    def use(self, tool_name: str) -> None:
        if self.used >= self.max_calls:
            raise BudgetExhausted(f"tool budget exhausted ({self.max_calls}); {tool_name} refused")
        self.used += 1
        assert self.calls is not None
        self.calls.append(tool_name)


class ThreatIntelTool:
    name = "threat_intel_lookup"

    def __init__(self, intel: ThreatIntel) -> None:
        self._intel = intel

    def lookup(self, value: str) -> dict[str, Any] | None:
        record = self._intel.lookup(value)
        if record is None:
            return None
        return {
            "value": value,
            "matched": record.matched_value,
            "confidence": record.confidence,
            "source": record.source,
            "tags": record.tags,
        }


class AssetHistoryTool:
    name = "asset_history"

    def __init__(self, history: list[Alert]) -> None:
        self._history = history

    def history_for(self, host: str | None) -> dict[str, Any]:
        if host is None:
            return {"host": None, "prior_alerts": 0}
        prior = [a for a in self._history if a.host == host]
        return {
            "host": host,
            "prior_alerts": len(prior),
            "prior_sources": sorted({a.source for a in prior}),
        }


class SimilarAlertsTool:
    name = "similar_alerts_search"

    def __init__(self, history: list[Alert]) -> None:
        self._history = history

    def similar_to(self, alert: Alert, *, limit: int = 5) -> list[str]:
        """Alerts sharing an endpoint or destination with this one."""
        matches: list[str] = []
        for other in self._history:
            if other.id == alert.id:
                continue
            shared = (alert.dst_ip and other.dst_ip == alert.dst_ip) or (
                alert.src_ip and other.src_ip == alert.src_ip and alert.src_ip != other.host
            )
            if shared:
                matches.append(other.id)
            if len(matches) >= limit:
                break
        return matches

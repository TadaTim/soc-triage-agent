"""Providers.

FakeProvider is the deterministic stand-in used by tests, the eval harness,
and local development — anywhere a run must work with NO real API keys. It
investigates the way the contract forces a real model to: it reads ONLY the
structured enrichment context embedded in the prompt and composes the report
from that evidence. It cannot invent IoCs because it never sees anything but
the enrichment's IoC list.

A production provider (Anthropic/OpenAI HTTP client) implements the same
LLMProvider protocol and is held to the same output contract by
InvestigationReport validation in the agent.
"""

from __future__ import annotations

import json
import time
from typing import Any

from packages.investigate.gateway import CompletionResult

CONTEXT_MARKER = "ENRICHMENT_CONTEXT_JSON:"

# Illustrative price book for the fake provider (per 1K tokens).
_PRICE_IN_PER_1K = 0.003
_PRICE_OUT_PER_1K = 0.015


class FakeProvider:
    name = "fake-deterministic"

    def complete(self, prompt: str, *, alert_id: str) -> CompletionResult:
        if CONTEXT_MARKER not in prompt:
            raise ValueError("prompt is missing the enrichment context block")
        context: dict[str, Any] = json.loads(prompt.split(CONTEXT_MARKER, 1)[1].strip())
        intel_hits: list[dict[str, Any]] = context["intel_hits"]
        ioc_values: list[str] = context["ioc_values"]
        score: float = context["score"]

        if intel_hits:
            top = max(intel_hits, key=lambda h: h["confidence"])
            report = {
                "alert_id": alert_id,
                "summary": (
                    f"Enrichment confirms a threat-intel match on {top['value']} "
                    f"(confidence {top['confidence']:.2f}, {top['source']}). "
                    "The activity is consistent with the matched indicator's tags "
                    f"{top.get('tags', [])}. No benign explanation is present in "
                    "the enrichment record."
                ),
                "ioc_values": [h["value"] for h in intel_hits],
                "severity_proposal": "high",
                "recommended_actions": ["collect_forensics", "request_containment_approval"],
                "confidence": 0.92,
            }
        elif score >= 40:
            report = {
                "alert_id": alert_id,
                "summary": (
                    "Deterministic enrichment found adverse signals but no "
                    "threat-intel confirmation. The evidence is genuinely "
                    "ambiguous; a human should decide with full context."
                ),
                "ioc_values": ioc_values[:3],
                "severity_proposal": "medium",
                "recommended_actions": ["escalate_to_ir"],
                "confidence": 0.45,
            }
        else:
            report = {
                "alert_id": alert_id,
                "summary": (
                    "Escalated with weak signals and no intel confirmation. "
                    "Insufficient evidence to call this malicious; route to a "
                    "human rather than close on a guess."
                ),
                "ioc_values": ioc_values[:2],
                "severity_proposal": "medium",
                "recommended_actions": ["monitor"],
                "confidence": 0.4,
            }

        tokens_in = max(1, len(prompt) // 4)
        tokens_out = 190
        cost = tokens_in / 1000 * _PRICE_IN_PER_1K + tokens_out / 1000 * _PRICE_OUT_PER_1K
        return CompletionResult(
            text=json.dumps(report),
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=round(cost, 6),
            model=self.name,
        )


class BrokenProvider:
    """Always fails — exercises gateway failure handling and the breaker."""

    name = "broken"

    def complete(self, prompt: str, *, alert_id: str) -> CompletionResult:
        raise RuntimeError("provider unavailable (simulated outage)")


class SlowProvider:
    """Sleeps past any sane timeout — exercises the gateway timeout path."""

    name = "slow"

    def __init__(self, delay_s: float = 30.0) -> None:
        self._delay_s = delay_s

    def complete(self, prompt: str, *, alert_id: str) -> CompletionResult:
        time.sleep(self._delay_s)
        return CompletionResult(text="{}", tokens_in=0, tokens_out=0, cost_usd=0.0, model=self.name)

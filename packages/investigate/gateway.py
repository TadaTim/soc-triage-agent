"""LLM gateway: provider abstraction with timeout, circuit breaker, and
per-investigation cost attribution.

Triage must never block on the model: if the provider is down, slow, or the
breaker is open, the gateway raises and the investigation layer degrades to
an enrichment-only verdict while deterministic triage continues.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from typing import Protocol


class ProviderError(Exception):
    """The provider failed (error response, malformed output, ...)."""


class ProviderTimeout(ProviderError):
    """The provider exceeded the gateway timeout."""


class CircuitOpenError(ProviderError):
    """The circuit breaker is open; the provider was not called."""


@dataclass(frozen=True)
class CompletionResult:
    text: str
    tokens_in: int
    tokens_out: int
    cost_usd: float
    model: str


class LLMProvider(Protocol):
    name: str

    def complete(self, prompt: str, *, alert_id: str) -> CompletionResult: ...


@dataclass
class CostEntry:
    alert_id: str
    model: str
    tokens_in: int
    tokens_out: int
    cost_usd: float


@dataclass
class CircuitBreaker:
    """Opens after `failure_threshold` consecutive provider failures.
    While open, calls fail fast. After `cooldown_s`, one trial call is
    allowed (half-open); success closes the breaker, failure re-opens it."""

    failure_threshold: int = 5
    cooldown_s: float = 60.0
    consecutive_failures: int = 0
    opened_at: float | None = None

    def allow(self, now: float | None = None) -> bool:
        if self.opened_at is None:
            return True
        now = time.monotonic() if now is None else now
        return now - self.opened_at >= self.cooldown_s

    def record_success(self) -> None:
        self.consecutive_failures = 0
        self.opened_at = None

    def record_failure(self) -> None:
        self.consecutive_failures += 1
        if self.consecutive_failures >= self.failure_threshold and self.opened_at is None:
            self.opened_at = time.monotonic()

    @property
    def is_open(self) -> bool:
        return self.opened_at is not None


@dataclass
class LLMGateway:
    provider: LLMProvider
    timeout_s: float = 20.0
    breaker: CircuitBreaker = field(default_factory=CircuitBreaker)
    cost_log: list[CostEntry] = field(default_factory=list)
    _executor: ThreadPoolExecutor = field(
        default_factory=lambda: ThreadPoolExecutor(max_workers=4, thread_name_prefix="llm")
    )

    def complete(self, prompt: str, *, alert_id: str) -> CompletionResult:
        if not self.breaker.allow():
            raise CircuitOpenError(
                f"circuit open after {self.breaker.consecutive_failures} consecutive failures"
            )
        future = self._executor.submit(self.provider.complete, prompt, alert_id=alert_id)
        try:
            result = future.result(timeout=self.timeout_s)
        except FutureTimeout as exc:
            self.breaker.record_failure()
            raise ProviderTimeout(f"provider exceeded {self.timeout_s}s timeout") from exc
        except Exception as exc:
            self.breaker.record_failure()
            raise ProviderError(f"provider call failed: {exc}") from exc
        self.breaker.record_success()
        self.cost_log.append(
            CostEntry(
                alert_id=alert_id,
                model=result.model,
                tokens_in=result.tokens_in,
                tokens_out=result.tokens_out,
                cost_usd=result.cost_usd,
            )
        )
        return result

    def cost_for(self, alert_id: str) -> float:
        return sum(entry.cost_usd for entry in self.cost_log if entry.alert_id == alert_id)

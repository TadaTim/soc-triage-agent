"""Consumer pipeline services: ingest -> dedup -> enrich -> investigate.

The services hold all pipeline logic and depend only on in-process stores
and the packages/* layers, so the full path is testable without a broker.
apps/consumers/kafka_runner.py is a thin transport shell over these
services for the real Kafka deployment.

Failure semantics:
- A payload that cannot be parsed is POISON: it goes straight to the
  dead-letter store with the parse error. Retrying a parse error five times
  would just crash-loop the partition.
- A handler that fails transiently is retried with exponential backoff and
  full jitter, max 5 attempts, then dead-lettered with its error history.
"""

from __future__ import annotations

import json
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from packages.enrich.dedup import DedupTracker
from packages.enrich.pipeline import Decision, EnrichmentPipeline
from packages.observability.metrics import Metrics
from packages.schemas.models import (
    Alert,
    ApprovalRequest,
    DeadLetterEntry,
    EnrichmentResult,
    Verdict,
)

STORM_LAG_THRESHOLD = 1000
MAX_ATTEMPTS = 5


class PoisonMessage(Exception):
    """Unparseable payload. Never retried — straight to dead-letter."""


@dataclass
class InMemoryStore:
    """Process-local stand-in for Postgres/Redis. The pipeline services use
    only this interface, so swapping in real persistence touches one class."""

    alerts: dict[str, Alert] = field(default_factory=dict)
    dedup_counts: dict[str, int] = field(default_factory=dict)
    enrichments: dict[str, EnrichmentResult] = field(default_factory=dict)
    verdicts: list[Verdict] = field(default_factory=list)
    approvals: dict[str, ApprovalRequest] = field(default_factory=dict)
    dead_letters: list[DeadLetterEntry] = field(default_factory=list)
    escalated: list[str] = field(default_factory=list)
    investigations: list[str] = field(default_factory=list)

    def latest_verdict(self, alert_id: str) -> Verdict | None:
        for verdict in reversed(self.verdicts):
            if verdict.alert_id == alert_id:
                return verdict
        return None

    def add_dead_letter(self, topic: str, payload: str, errors: list[str], attempts: int) -> None:
        self.dead_letters.append(
            DeadLetterEntry(
                id=f"dl-{len(self.dead_letters) + 1:04d}",
                topic=topic,
                payload=payload,
                error_history=errors,
                attempts=attempts,
                created_at=datetime.now(UTC),
            )
        )


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = MAX_ATTEMPTS
    base_delay_s: float = 0.5
    max_delay_s: float = 30.0

    def delay_for(self, attempt: int, rng: random.Random) -> float:
        """Exponential backoff with full jitter."""
        cap = min(self.max_delay_s, self.base_delay_s * (2**attempt))
        return rng.uniform(0.0, cap)


@dataclass
class Outcome:
    status: str  # ok | duplicate | dead_lettered
    attempts: int
    detail: str = ""


def run_with_retries(
    handler: Callable[[], None],
    *,
    topic: str,
    payload: str,
    store: InMemoryStore,
    policy: RetryPolicy | None = None,
    sleeper: Callable[[float], None] = time.sleep,
    rng: random.Random | None = None,
    metrics: Metrics | None = None,
) -> Outcome:
    """Run handler under the retry/DLQ policy. Poison goes straight to the
    dead-letter store; transient failures get up to policy.max_attempts."""
    policy = policy or RetryPolicy()
    rng = rng or random.Random(0)
    errors: list[str] = []
    for attempt in range(1, policy.max_attempts + 1):
        try:
            handler()
            return Outcome(status="ok", attempts=attempt)
        except PoisonMessage as exc:
            errors.append(f"attempt {attempt}: poison: {exc}")
            store.add_dead_letter(topic, payload, errors, attempts=attempt)
            if metrics is not None:
                metrics.set_gauge("soc_dlq_depth", float(len(store.dead_letters)))
            return Outcome(status="dead_lettered", attempts=attempt, detail="poison")
        except Exception as exc:
            errors.append(f"attempt {attempt}: {type(exc).__name__}: {exc}")
            if attempt < policy.max_attempts:
                sleeper(policy.delay_for(attempt, rng))
    store.add_dead_letter(topic, payload, errors, attempts=policy.max_attempts)
    if metrics is not None:
        metrics.set_gauge("soc_dlq_depth", float(len(store.dead_letters)))
    return Outcome(status="dead_lettered", attempts=policy.max_attempts, detail="exhausted")


# ---------------------------------------------------------------- services --


@dataclass
class IngestResult:
    alert: Alert
    duplicate: bool
    dedup_count: int


class IngestService:
    """Normalize raw payloads into Alerts and collapse duplicates."""

    def __init__(
        self, store: InMemoryStore, dedup: DedupTracker, metrics: Metrics | None = None
    ) -> None:
        self._store = store
        self._dedup = dedup
        self._metrics = metrics

    def parse(self, raw: str) -> Alert:
        try:
            data = json.loads(raw)
            return Alert(**data)
        except Exception as exc:
            raise PoisonMessage(f"unparseable alert payload: {exc}") from exc

    def ingest(self, alert: Alert) -> IngestResult:
        if self._metrics is not None:
            self._metrics.inc("soc_alerts_ingested_total")
        duplicate, canonical_id, count = self._dedup.check(alert)
        if duplicate:
            if self._metrics is not None:
                self._metrics.inc("soc_alerts_duplicated_total")
            self._store.dedup_counts[canonical_id] = count
            canonical = self._store.alerts[canonical_id]
            return IngestResult(alert=canonical, duplicate=True, dedup_count=count)
        self._store.alerts[alert.id] = alert
        self._store.dedup_counts[alert.id] = count
        return IngestResult(alert=alert, duplicate=False, dedup_count=count)


class EnrichService:
    """Deterministic enrichment + verdict. In storm mode (consumer lag above
    threshold) enrichment degrades explicitly: results are flagged degraded
    and optional work is shed so verdict latency is protected."""

    def __init__(
        self,
        store: InMemoryStore,
        pipeline: EnrichmentPipeline,
        metrics: Metrics | None = None,
    ) -> None:
        self._store = store
        self._pipeline = pipeline
        self._metrics = metrics
        self._verdict_seq = 0

    def process(self, alert_id: str, *, consumer_lag: int = 0) -> Decision:
        started = time.perf_counter()
        alert = self._store.alerts[alert_id]
        storm = consumer_lag > STORM_LAG_THRESHOLD
        result = self._pipeline.enrich(alert, storm_mode=storm)
        self._store.enrichments[alert_id] = result
        self._verdict_seq += 1
        decision = self._pipeline.decide(alert, result, verdict_id=f"v-{self._verdict_seq:05d}")
        if decision.verdict is not None:
            self._store.verdicts.append(decision.verdict)
        else:
            self._store.escalated.append(alert_id)
        if self._metrics is not None:
            self._metrics.observe(
                "soc_verdict_latency_seconds", time.perf_counter() - started, {"stage": "enrich"}
            )
            self._metrics.set_gauge("soc_storm_mode", 1.0 if storm else 0.0)
            self._metrics.set_gauge("soc_consumer_lag", float(consumer_lag))
            if decision.verdict is not None:
                self._metrics.inc(
                    "soc_verdicts_total",
                    {"stage": "enrich", "disposition": decision.verdict.disposition.value},
                )
            else:
                self._metrics.inc("soc_escalations_total")
        return decision

    def reprocess_late_event(self, alert: Alert) -> Verdict:
        """A late/out-of-order event for an already-verdicted alert RE-OPENS
        the verdict: a new verdict is appended with supersedes_id pointing
        at the one it replaces. History is never silently rewritten. If the
        deterministic layer cannot resolve the late event, the re-opened
        verdict is needs_human (decided by the deterministic layer's refusal
        to guess)."""
        from packages.schemas.models import DecidedBy, Disposition

        previous = self._store.latest_verdict(alert.id)
        result = self._pipeline.enrich(alert)
        self._store.enrichments[alert.id] = result
        self._verdict_seq += 1
        decision = self._pipeline.decide(alert, result, verdict_id=f"v-{self._verdict_seq:05d}")
        if decision.verdict is not None:
            verdict = decision.verdict
        else:
            verdict = Verdict(
                id=f"v-{self._verdict_seq:05d}",
                alert_id=alert.id,
                disposition=Disposition.NEEDS_HUMAN,
                decided_by=DecidedBy.DETERMINISTIC,
                rationale=f"late event re-opened verdict; {decision.reason}",
                score=result.score,
                lineage=[f"enrichment:{alert.id}", *result.signals],
                created_at=alert.ingest_time,
            )
        if previous is not None:
            verdict = verdict.model_copy(update={"supersedes_id": previous.id})
        self._store.verdicts.append(verdict)
        return verdict


class InvestigationProcessor(Protocol):
    """Structural type for the escalation sink (packages.investigate's
    InvestigationService) — kept as a protocol so consumers never import
    the AI layer directly."""

    def process(self, alert_id: str) -> object: ...


class TriageOrchestrator:
    """The full in-process path: ingest -> dedup -> enrich -> verdict, with
    escalations handed to the investigation service when one is attached."""

    def __init__(
        self,
        store: InMemoryStore,
        ingest: IngestService,
        enrich: EnrichService,
        investigate: InvestigationProcessor | None = None,
        metrics: Metrics | None = None,
    ) -> None:
        self.store = store
        self.metrics = metrics or Metrics()
        self._ingest = ingest
        self._enrich = enrich
        self._investigate = investigate

    @classmethod
    def create(
        cls,
        investigate: InvestigationProcessor | None = None,
        metrics: Metrics | None = None,
    ) -> TriageOrchestrator:
        store = InMemoryStore()
        metrics = metrics or Metrics()
        pipeline = EnrichmentPipeline.from_data_dir()
        return cls(
            store=store,
            ingest=IngestService(store, DedupTracker(), metrics),
            enrich=EnrichService(store, pipeline, metrics),
            investigate=investigate,
            metrics=metrics,
        )

    def handle_raw(self, raw: str, *, consumer_lag: int = 0) -> Outcome:
        """Entry point mirroring the Kafka consumer: parse under the retry
        policy, dedup, enrich, escalate."""
        holder: dict[str, IngestResult] = {}

        def _ingest() -> None:
            alert = self._ingest.parse(raw)
            holder["result"] = self._ingest.ingest(alert)

        outcome = run_with_retries(
            _ingest, topic="alerts.raw", payload=raw, store=self.store, metrics=self.metrics
        )
        if outcome.status != "ok":
            return outcome
        result = holder["result"]
        if result.duplicate:
            return Outcome(
                status="duplicate",
                attempts=outcome.attempts,
                detail=f"dedup_count={result.dedup_count}",
            )
        decision = self._enrich.process(result.alert.id, consumer_lag=consumer_lag)
        if decision.escalate and self._investigate is not None:
            self._investigate.process(result.alert.id)
        return outcome

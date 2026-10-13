"""Consumer semantics: retries, dead letters, dedup storms, storm mode,
and verdict re-opening on late events."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from apps.consumers.services import (
    InMemoryStore,
    PoisonMessage,
    RetryPolicy,
    TriageOrchestrator,
    run_with_retries,
)
from packages.schemas.models import Alert, Disposition, Severity

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)


def raw_alert(**overrides: object) -> str:
    fields: dict[str, object] = {
        "id": "c-1",
        "source": "edr",
        "sensor_id": "edr-1",
        "severity": "medium",
        "title": "Encoded powershell",
        "event_time": NOW.isoformat(),
        "ingest_time": NOW.isoformat(),
        "payload": "powershell.exe -enc SQBFAFgA ran on the host",
        "host": "WS-1001",
    }
    fields.update(overrides)
    return json.dumps(fields)


def test_transient_failure_retries_then_succeeds() -> None:
    store = InMemoryStore()
    calls = {"n": 0}

    def flaky() -> None:
        calls["n"] += 1
        if calls["n"] < 3:
            raise RuntimeError("broker hiccup")

    outcome = run_with_retries(
        flaky,
        topic="t",
        payload="p",
        store=store,
        policy=RetryPolicy(base_delay_s=0.0),
        sleeper=lambda s: None,
    )
    assert outcome.status == "ok"
    assert outcome.attempts == 3
    assert store.dead_letters == []


def test_exhaustion_dead_letters_after_exactly_five_attempts() -> None:
    store = InMemoryStore()

    def always_fail() -> None:
        raise RuntimeError("downstream down")

    outcome = run_with_retries(
        always_fail,
        topic="alerts.raw",
        payload="p",
        store=store,
        policy=RetryPolicy(base_delay_s=0.0),
        sleeper=lambda s: None,
    )
    assert outcome.status == "dead_lettered"
    assert outcome.attempts == 5
    assert len(store.dead_letters) == 1
    entry = store.dead_letters[0]
    assert entry.attempts == 5
    assert len(entry.error_history) == 5
    assert "downstream down" in entry.error_history[-1]


def test_poison_goes_straight_to_dead_letter() -> None:
    store = InMemoryStore()

    def poison() -> None:
        raise PoisonMessage("unparseable")

    outcome = run_with_retries(
        poison,
        topic="alerts.raw",
        payload="{not json",
        store=store,
        policy=RetryPolicy(base_delay_s=0.0),
        sleeper=lambda s: None,
    )
    assert outcome.status == "dead_lettered"
    assert outcome.attempts == 1  # no crash-looping a partition on parse errors
    assert store.dead_letters[0].attempts == 1


def test_unparseable_raw_message_dead_letters_via_orchestrator() -> None:
    orch = TriageOrchestrator.create()
    outcome = orch.handle_raw("{definitely not json")
    assert outcome.status == "dead_lettered"
    assert len(orch.store.dead_letters) == 1


def test_fifty_duplicate_burst_creates_one_alert_one_investigation() -> None:
    """The Stage 4 validation: a 50x duplicate burst collapses to a single
    alert and — because the alert escalates — exactly one investigation."""
    orch = TriageOrchestrator.create()
    from packages.investigate.agent import InvestigationService
    from packages.investigate.gateway import LLMGateway
    from packages.investigate.providers import FakeProvider

    orch._investigate = InvestigationService(orch.store, LLMGateway(FakeProvider()))
    raw = raw_alert()
    statuses = [orch.handle_raw(raw).status for _ in range(50)]
    assert statuses[0] == "ok"
    assert statuses.count("duplicate") == 49
    assert len(orch.store.alerts) == 1
    assert orch.store.dedup_counts["c-1"] == 50
    assert len(orch.store.investigations) == 1
    verdicts = [v for v in orch.store.verdicts if v.alert_id == "c-1"]
    assert len(verdicts) == 1
    assert verdicts[0].disposition == Disposition.NEEDS_HUMAN


def test_storm_mode_degrades_enrichment() -> None:
    orch = TriageOrchestrator.create()
    orch.handle_raw(raw_alert(id="s-1"), consumer_lag=5000)
    assert orch.store.enrichments["s-1"].degraded is True
    orch2 = TriageOrchestrator.create()
    orch2.handle_raw(raw_alert(id="s-2"), consumer_lag=10)
    assert orch2.store.enrichments["s-2"].degraded is False


def test_late_event_reopens_verdict_explicitly() -> None:
    orch = TriageOrchestrator.create()
    raw = raw_alert(
        id="late-1",
        title="Beaconing",
        payload="beacon to 185.220.101.7 every 60s",
        dst_ip="185.220.101.7",
    )
    orch.handle_raw(raw)
    first = orch.store.latest_verdict("late-1")
    assert first is not None and first.disposition == Disposition.MALICIOUS

    # A late-arriving correction: the "beacon" destination was reached from
    # the allowlisted scanner during a health check window.
    late = Alert(
        id="late-1",
        source="edr",
        sensor_id="edr-1",
        severity=Severity.MEDIUM,
        title="Beaconing",
        event_time=NOW - timedelta(hours=2),
        ingest_time=NOW,
        payload="beacon to 185.220.101.7 every 60s",
        src_ip="10.13.0.50",
        dst_ip="185.220.101.7",
        host="WS-1001",
    )
    reopened = orch._enrich.reprocess_late_event(late)
    assert reopened.supersedes_id == first.id
    assert orch.store.latest_verdict("late-1") == reopened
    assert len([v for v in orch.store.verdicts if v.alert_id == "late-1"]) == 2

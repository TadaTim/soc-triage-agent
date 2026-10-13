"""Eval harness entry point: `python -m packages.evals`.

Runs every golden alert through the real triage path in-process —
deterministic enrichment first, bounded investigation (FakeProvider) for
escalations — then scores the outcomes and exits non-zero on any gate miss.
Each alert gets an isolated store so dedup correlation cannot leak across
eval cases (dedup is exercised separately in the test suite).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from apps.consumers.services import EnrichService, InMemoryStore
from packages.enrich.pipeline import EnrichmentPipeline
from packages.evals.scoring import AlertOutcome, score
from packages.investigate.agent import InvestigationService
from packages.investigate.gateway import LLMGateway
from packages.investigate.providers import FakeProvider
from packages.schemas.models import Alert

DATASET = Path(__file__).with_name("dataset.jsonl")
ALERT_FIELDS = (
    "id",
    "source",
    "sensor_id",
    "severity",
    "title",
    "event_time",
    "ingest_time",
    "payload",
    "src_ip",
    "dst_ip",
    "host",
    "user",
)


def load_golden() -> list[dict[str, object]]:
    return [json.loads(line) for line in DATASET.read_text().splitlines() if line.strip()]


def run() -> int:
    pipeline = EnrichmentPipeline.from_data_dir()
    gateway = LLMGateway(FakeProvider())
    outcomes: list[AlertOutcome] = []

    for record in load_golden():
        alert = Alert(**{k: record[k] for k in ALERT_FIELDS})
        store = InMemoryStore()
        store.alerts[alert.id] = alert
        enrich = EnrichService(store, pipeline)
        decision = enrich.process(alert.id)
        if decision.escalate:
            service = InvestigationService(store, gateway)
            service.process(alert.id)
        verdict = store.latest_verdict(alert.id)
        assert verdict is not None, f"no verdict produced for {alert.id}"
        enrichment = store.enrichments[alert.id]
        outcomes.append(
            AlertOutcome(
                alert_id=alert.id,
                expected=str(record["expected_disposition"]),
                final_disposition=verdict.disposition.value,
                decided_by=verdict.decided_by.value,
                cost_usd=gateway.cost_for(alert.id),
                extracted_iocs={(ioc.type.value, ioc.value) for ioc in enrichment.iocs},
                expected_iocs={
                    (str(ioc["type"]), str(ioc["value"]))
                    for ioc in record["expected_iocs"]  # type: ignore[attr-defined]
                },
            )
        )

    card = score(outcomes)
    print(card.render())
    return 0 if card.passed else 1


if __name__ == "__main__":
    sys.exit(run())

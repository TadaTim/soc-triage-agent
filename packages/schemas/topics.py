"""Kafka topic definitions as code. Topics are provisioned from this module
(apps/consumers/kafka_runner.ensure_topics); nobody creates topics by hand
in a console, so a fresh environment is reproducible from the repo alone."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TopicSpec:
    name: str
    partitions: int
    retention_ms: int
    description: str


_DAY_MS = 86_400_000

TOPICS: dict[str, TopicSpec] = {
    spec.name: spec
    for spec in [
        TopicSpec(
            "alerts.raw", 12, 7 * _DAY_MS, "Raw alert webhooks as received, pre-normalization."
        ),
        TopicSpec("alerts.normalized", 12, 7 * _DAY_MS, "Normalized Alert records, deduplicated."),
        TopicSpec("alerts.enriched", 12, 7 * _DAY_MS, "Alerts with EnrichmentResult attached."),
        TopicSpec(
            "alerts.escalated", 6, 14 * _DAY_MS, "Alerts the deterministic layer could not resolve."
        ),
        TopicSpec("verdicts", 12, 30 * _DAY_MS, "Append-only Verdict records."),
        TopicSpec(
            "alerts.dlq", 6, 30 * _DAY_MS, "Dead letters: poison payloads and exhausted retries."
        ),
    ]
}

RAW_TOPIC = "alerts.raw"
NORMALIZED_TOPIC = "alerts.normalized"
ENRICHED_TOPIC = "alerts.enriched"
ESCALATED_TOPIC = "alerts.escalated"
VERDICTS_TOPIC = "verdicts"
DLQ_TOPIC = "alerts.dlq"

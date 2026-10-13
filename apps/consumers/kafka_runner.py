"""Thin Kafka transport shell over apps.consumers.services.

All pipeline logic lives in services.py; this module only moves bytes:
provision topics (from packages/schemas/topics.py — topics are code, never
console-created), consume alerts.raw, hand payloads to the orchestrator,
and publish verdicts. It requires a live broker (Redpanda in
docker-compose.yml) and the kafka-python package; imports are lazy so the
rest of the system — including the full test suite and eval harness — runs
without either.
"""

from __future__ import annotations

import os
from typing import Any

from apps.consumers.services import TriageOrchestrator
from packages.schemas.topics import DLQ_TOPIC, RAW_TOPIC, TOPICS, VERDICTS_TOPIC


def ensure_topics(bootstrap_servers: str) -> None:
    """Create any missing topics from the code-defined TOPICS specs."""
    from kafka.admin import KafkaAdminClient, NewTopic

    admin = KafkaAdminClient(bootstrap_servers=bootstrap_servers, client_id="soc-provisioner")
    existing = set(admin.list_topics())
    missing = [
        NewTopic(name=spec.name, num_partitions=spec.partitions, replication_factor=1)
        for spec in TOPICS.values()
        if spec.name not in existing
    ]
    if missing:
        admin.create_topics(new_topics=missing, validate_only=False)
    admin.close()


def run_consumer(bootstrap_servers: str | None = None) -> None:  # pragma: no cover - needs broker
    """Consume alerts.raw forever, publishing verdicts and dead letters."""
    from kafka import KafkaConsumer, KafkaProducer

    servers = bootstrap_servers or os.environ.get("SOC_KAFKA_BOOTSTRAP", "localhost:19092")
    ensure_topics(servers)
    consumer: Any = KafkaConsumer(
        RAW_TOPIC,
        bootstrap_servers=servers,
        group_id="soc-triage",
        enable_auto_commit=False,
        value_deserializer=lambda b: b.decode("utf-8"),
    )
    producer: Any = KafkaProducer(bootstrap_servers=servers)
    orchestrator = TriageOrchestrator.create()
    known_dead_letters = 0
    known_verdicts = 0
    for message in consumer:
        lag = 0  # production wires consumer lag metrics here (Stage 8)
        outcome = orchestrator.handle_raw(message.value, consumer_lag=lag)
        # Publish any new verdicts / dead letters produced by this message.
        for verdict in orchestrator.store.verdicts[known_verdicts:]:
            producer.send(VERDICTS_TOPIC, value=verdict.model_dump_json().encode())
        known_verdicts = len(orchestrator.store.verdicts)
        new_dead = orchestrator.store.dead_letters[known_dead_letters:]
        for entry in new_dead:
            producer.send(DLQ_TOPIC, value=entry.model_dump_json().encode())
        known_dead_letters = len(orchestrator.store.dead_letters)
        consumer.commit()
        _ = outcome


if __name__ == "__main__":  # pragma: no cover
    run_consumer()

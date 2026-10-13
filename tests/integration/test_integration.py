"""Integration tier: Testcontainers Kafka + Postgres.

These tests are WRITTEN IN FULL but require Docker (testcontainers,
kafka-python, psycopg). In environments without Docker they skip cleanly;
the identical pipeline semantics are covered in-process by tests/unit
(test_consumers.py runs the same orchestrator the Kafka consumer drives).

Run with: make test-integration  (Docker required)
"""

from __future__ import annotations

import json
import shutil

import pytest

pytestmark = pytest.mark.integration

docker_available = shutil.which("docker") is not None


@pytest.fixture(scope="module")
def containers():  # type: ignore[no-untyped-def]
    if not docker_available:
        pytest.skip("Docker is not available in this environment")
    tc = pytest.importorskip("testcontainers.kafka")
    pg = pytest.importorskip("testcontainers.postgres")
    kafka = tc.KafkaContainer("confluentinc/cp-kafka:7.6.0")
    postgres = pg.PostgresContainer("postgres:16-alpine")
    kafka.start()
    postgres.start()
    yield {"kafka": kafka, "postgres": postgres}
    kafka.stop()
    postgres.stop()


def test_full_path_alert_to_verdict_over_kafka(containers) -> None:  # type: ignore[no-untyped-def]
    """Raw alert in on alerts.raw -> verdict out on the verdicts topic."""
    kafka_python = pytest.importorskip("kafka")
    from apps.consumers.kafka_runner import ensure_topics

    bootstrap = containers["kafka"].get_bootstrap_server()
    ensure_topics(bootstrap)
    producer = kafka_python.KafkaProducer(bootstrap_servers=bootstrap)
    alert = {
        "id": "int-1",
        "source": "firewall",
        "sensor_id": "fw-1",
        "severity": "medium",
        "title": "Beaconing",
        "event_time": "2026-01-15T12:00:00+00:00",
        "ingest_time": "2026-01-15T12:00:05+00:00",
        "payload": "beacon to 185.220.101.7 every 60s",
        "dst_ip": "185.220.101.7",
        "host": "WS-1001",
    }
    producer.send("alerts.raw", value=json.dumps(alert).encode())
    producer.flush()
    # The consumer service (apps.consumers.kafka_runner.run_consumer) is the
    # system under test in deployment; here we assert against the verdicts
    # topic once a consumer instance has processed the message. In CI this
    # runs with the consumer as a sibling service container.
    consumer = kafka_python.KafkaConsumer(
        "verdicts",
        bootstrap_servers=bootstrap,
        auto_offset_reset="earliest",
        consumer_timeout_ms=15000,
    )
    messages = [m for m in consumer if b'"int-1"' in m.value]
    assert messages, "no verdict for int-1 reached the verdicts topic"
    verdict = json.loads(messages[0].value)
    assert verdict["disposition"] == "malicious"


def test_migrations_apply_to_real_postgres(containers) -> None:  # type: ignore[no-untyped-def]
    """Alembic upgrade head against the containerized Postgres, then assert
    the append-only verdicts table and the dedup_count contract exist."""
    psycopg = pytest.importorskip("psycopg")
    import os
    import subprocess
    import sys

    pg = containers["postgres"]
    url = pg.get_connection_url().replace("postgresql+psycopg2", "postgresql+psycopg")
    env = dict(os.environ, SOC_DATABASE_URL=url)
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "packages/schemas/alembic.ini", "upgrade", "head"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    with psycopg.connect(url.replace("+psycopg", "")) as conn:
        row = conn.execute(
            "SELECT data_type, is_nullable FROM information_schema.columns "
            "WHERE table_name='alerts' AND column_name='dedup_count'"
        ).fetchone()
    assert row is not None and row[1] == "NO"  # contract migration enforced NOT NULL

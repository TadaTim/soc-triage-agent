"""Observability: structured logs (hash-only payloads), metrics registry,
trace propagation, and service wiring."""

from __future__ import annotations

import io
import json
import logging

from apps.consumers.services import TriageOrchestrator
from packages.observability.logging import JsonFormatter, get_logger, payload_hash
from packages.observability.metrics import Metrics
from packages.observability.tracing import (
    configure_tracing,
    extract_context,
    get_tracer,
    inject_headers,
)


def test_json_log_line_carries_ids_and_never_payload() -> None:
    logger = get_logger("test-json")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger.handlers = [handler]
    secret_payload = "beacon to 185.220.101.7 with credentials hunter2"
    logger.info(
        "verdict issued",
        extra={
            "alert_id": "a-1",
            "trace_id": "t-9",
            "stage": "enrich",
            "disposition": "malicious",
        },
    )
    line = stream.getvalue()
    entry = json.loads(line)
    assert entry["alert_id"] == "a-1"
    assert entry["disposition"] == "malicious"
    assert "hunter2" not in line and "185.220.101.7" not in line
    # The sanctioned correlation path is the hash:
    assert payload_hash(secret_payload) != secret_payload
    assert len(payload_hash(secret_payload)) == 64


def test_metrics_counters_gauges_histograms_render() -> None:
    metrics = Metrics()
    metrics.inc("soc_alerts_ingested_total")
    metrics.inc("soc_alerts_ingested_total")
    metrics.inc("soc_alerts_duplicated_total")
    metrics.set_gauge("soc_dlq_depth", 3.0)
    metrics.observe("soc_verdict_latency_seconds", 0.42, {"stage": "enrich"})
    text = metrics.render_prometheus()
    assert "soc_alerts_ingested_total 2.0" in text
    assert 'soc_verdict_latency_seconds_bucket{le="0.5",stage="enrich"} 1' in text
    assert "soc_dlq_depth 3.0" in text
    assert metrics.counter_value("soc_alerts_duplicated_total") == 1.0


def test_trace_headers_round_trip() -> None:
    memory = configure_tracing()
    tracer = get_tracer()
    with tracer.start_as_current_span("ingest") as span:
        headers = inject_headers()
        assert "traceparent" in headers
        span.set_attribute("alert_id", "a-1")
    context = extract_context(headers)
    assert context is not None
    with tracer.start_as_current_span("verdict", context=context):
        pass
    assert memory is not None
    finished = memory.get_finished_spans()
    names = [s.name for s in finished]
    assert "ingest" in names and "verdict" in names
    # Both spans belong to one trace:
    assert len({s.context.trace_id for s in finished}) == 1


def test_services_emit_metrics() -> None:
    orch = TriageOrchestrator.create()
    raw = (
        '{"id": "m-1", "source": "edr", "sensor_id": "e1", "severity": "medium",'
        ' "title": "Encoded powershell", "event_time": "2026-01-15T12:00:00+00:00",'
        ' "ingest_time": "2026-01-15T12:00:01+00:00",'
        ' "payload": "powershell.exe -enc SQBFAFgA ran", "host": "WS-1001"}'
    )
    orch.handle_raw(raw)
    orch.handle_raw(raw)  # duplicate
    metrics = orch.metrics
    assert metrics.counter_value("soc_alerts_ingested_total") == 2.0
    assert metrics.counter_value("soc_alerts_duplicated_total") == 1.0
    assert metrics.counter_value("soc_escalations_total") == 1.0
    text = metrics.render_prometheus()
    assert "soc_verdict_latency_seconds" in text

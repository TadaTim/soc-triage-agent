"""OpenTelemetry tracing with Kafka header propagation.

One alert = one trace from ingest to verdict. Because the pipeline crosses
Kafka topics, trace context travels in message headers (W3C traceparent)
via inject/extract helpers — the consumer attaches to the producer's span
instead of starting a disconnected trace.
"""

from __future__ import annotations

from typing import Any

from opentelemetry import propagate, trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

_configured = False


def configure_tracing(exporter: SpanExporter | None = None) -> InMemorySpanExporter | None:
    """Install a TracerProvider. With no exporter (local/tests), spans go to
    an in-memory exporter that is returned for inspection. In deployment an
    OTLP exporter is passed and spans flow to Tempo (docker-compose)."""
    global _configured
    provider = TracerProvider()
    memory: InMemorySpanExporter | None = None
    if exporter is None:
        memory = InMemorySpanExporter()
        provider.add_span_processor(SimpleSpanProcessor(memory))
    else:
        provider.add_span_processor(SimpleSpanProcessor(exporter))
    if not _configured:
        try:
            trace.set_tracer_provider(provider)
            _configured = True
        except Exception:  # a provider is already set (tests, reloads)
            pass
    return memory


def get_tracer(name: str = "soc-triage") -> Any:
    return trace.get_tracer(name)


def inject_headers(headers: dict[str, str] | None = None) -> dict[str, str]:
    """Serialize the current trace context into Kafka message headers."""
    carrier: dict[str, str] = dict(headers or {})
    propagate.inject(carrier)
    return carrier


def extract_context(headers: dict[str, str]) -> Any:
    """Restore trace context from Kafka message headers (use as the parent
    context for consumer spans)."""
    return propagate.extract(headers)

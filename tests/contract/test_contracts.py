"""Contract tests (Stage 2): the safety shapes of the system.

These are architectural guarantees expressed as tests:
1. An InvestigationReport citing an IoC that enrichment never produced
   fails validation.
2. The API surface contains no route that executes containment.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from apps.api.main import app
from packages.schemas.models import (
    Alert,
    EnrichmentResult,
    InvestigationReport,
    IoC,
    IoCType,
    Severity,
)

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)


def make_alert(payload: str = "beacon to 185.220.101.7 every 60s") -> Alert:
    return Alert(
        id="a-1",
        source="edr",
        sensor_id="edr-07",
        severity=Severity.MEDIUM,
        title="Beaconing",
        event_time=NOW,
        ingest_time=NOW,
        payload=payload,
        dst_ip="185.220.101.7",
        host="WS-1042",
    )


def make_enrichment(alert: Alert) -> EnrichmentResult:
    start = alert.payload.index("185.220.101.7")
    return EnrichmentResult(
        alert_id=alert.id,
        iocs=[
            IoC(
                type=IoCType.IPV4,
                value="185.220.101.7",
                raw="185.220.101.7",
                start=start,
                end=start + len("185.220.101.7"),
            )
        ],
    )


def test_payload_hash_is_computed() -> None:
    alert = make_alert()
    assert len(alert.payload_hash) == 64


def test_report_citing_real_ioc_validates() -> None:
    alert = make_alert()
    enrichment = make_enrichment(alert)
    report = InvestigationReport(
        alert_id=alert.id,
        summary="Known C2 beacon",
        ioc_values=["185.220.101.7"],
        severity_proposal=Severity.HIGH,
        confidence=0.9,
    )
    report.validate_iocs(enrichment)  # must not raise


def test_report_citing_invented_ioc_fails_validation() -> None:
    alert = make_alert()
    enrichment = make_enrichment(alert)
    report = InvestigationReport(
        alert_id=alert.id,
        summary="Model hallucinated a second indicator",
        ioc_values=["185.220.101.7", "203.0.113.99"],
        severity_proposal=Severity.HIGH,
        confidence=0.9,
    )
    with pytest.raises(ValueError, match="absent from enrichment"):
        report.validate_iocs(enrichment)


def test_ioc_span_must_be_forward() -> None:
    with pytest.raises(ValueError):
        IoC(type=IoCType.DOMAIN, value="x.example", raw="x", start=5, end=5)


def test_api_has_no_containment_execution_route() -> None:
    """Containment may only ever be *requested* (ApprovalRequest) and
    *decided* by a human. No route may execute it."""
    paths = [route.path for route in app.routes]  # type: ignore[attr-defined]
    for path in paths:
        lowered = path.lower()
        assert "execute" not in lowered
        assert "contain" not in lowered
        assert "isolate" not in lowered
        assert "block" not in lowered
    # Sanity: the approval console itself exists (added in Stage 4 wiring,
    # but /health must already be there).
    assert "/health" in paths

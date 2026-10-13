"""Investigation agent: budget, validation, degradation, cost."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from apps.consumers.services import InMemoryStore
from packages.enrich.pipeline import EnrichmentPipeline
from packages.investigate.agent import InvestigationAgent, InvestigationService
from packages.investigate.gateway import (
    CircuitOpenError,
    CompletionResult,
    LLMGateway,
    ProviderError,
)
from packages.investigate.providers import BrokenProvider, FakeProvider, SlowProvider
from packages.investigate.tools import (
    AssetHistoryTool,
    BudgetExhausted,
    SimilarAlertsTool,
    ThreatIntelTool,
    ToolBudget,
)
from packages.schemas.models import Alert, Disposition, Severity

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def pipeline() -> EnrichmentPipeline:
    return EnrichmentPipeline.from_data_dir()


def make_agent(gateway: LLMGateway) -> InvestigationAgent:
    from packages.enrich.intel import ThreatIntel

    return InvestigationAgent(
        gateway,
        ThreatIntelTool(ThreatIntel.from_data_dir()),
        AssetHistoryTool([]),
        SimilarAlertsTool([]),
    )


def escalated_alert(pipeline: EnrichmentPipeline, payload: str, **kw: object):  # type: ignore[no-untyped-def]
    fields: dict[str, object] = {
        "id": "inv-1",
        "source": "edr",
        "sensor_id": "edr-1",
        "severity": Severity.MEDIUM,
        "title": "t",
        "event_time": NOW,
        "ingest_time": NOW,
        "payload": payload,
    }
    fields.update(kw)
    alert = Alert(**fields)  # type: ignore[arg-type]
    enrichment = pipeline.enrich(alert)
    decision = pipeline.decide(alert, enrichment, verdict_id="v0")
    assert decision.escalate, "fixture alert must escalate"
    return alert, enrichment


def test_tool_budget_is_hard(pipeline: EnrichmentPipeline) -> None:
    budget = ToolBudget(max_calls=3)
    budget.use("a")
    budget.use("b")
    budget.use("c")
    with pytest.raises(BudgetExhausted):
        budget.use("d")
    assert budget.used == 3


def test_investigation_of_intel_case_is_malicious(pipeline: EnrichmentPipeline) -> None:
    # C2 to a known-bad IP, but on the pentest host inside its window, so the
    # deterministic layer escalates instead of deciding.
    alert, enrichment = escalated_alert(
        pipeline,
        "beaconing to 185.220.101.7 at regular intervals",
        host="WS-1031",
        event_time=datetime(2026, 1, 14, 10, 0, tzinfo=UTC),
        dst_ip="185.220.101.7",
    )
    agent = make_agent(LLMGateway(FakeProvider()))
    outcome = agent.investigate(alert, enrichment, verdict_id="v1")
    assert outcome.report is not None
    assert outcome.verdict.disposition == Disposition.MALICIOUS
    assert outcome.tool_calls <= 3
    assert outcome.cost_usd > 0


def test_investigation_of_ambiguous_case_goes_to_human(
    pipeline: EnrichmentPipeline,
) -> None:
    alert, enrichment = escalated_alert(pipeline, "powershell.exe -enc SQBFAFgA observed")
    agent = make_agent(LLMGateway(FakeProvider()))
    outcome = agent.investigate(alert, enrichment, verdict_id="v1")
    assert outcome.verdict.disposition == Disposition.NEEDS_HUMAN


def test_provider_outage_degrades_to_enrichment_only(
    pipeline: EnrichmentPipeline,
) -> None:
    alert, enrichment = escalated_alert(pipeline, "powershell.exe -enc SQBFAFgA observed")
    agent = make_agent(LLMGateway(BrokenProvider()))
    outcome = agent.investigate(alert, enrichment, verdict_id="v1")
    assert outcome.report is None
    assert outcome.verdict.disposition == Disposition.NEEDS_HUMAN
    assert outcome.error is not None


def test_circuit_breaker_opens_after_five_failures() -> None:
    gateway = LLMGateway(BrokenProvider())
    for _ in range(5):
        with pytest.raises(ProviderError):
            gateway.complete("prompt", alert_id="x")
    with pytest.raises(CircuitOpenError):
        gateway.complete("prompt", alert_id="x")


def test_gateway_timeout(pipeline: EnrichmentPipeline) -> None:
    alert, enrichment = escalated_alert(pipeline, "powershell.exe -enc SQBFAFgA observed")
    gateway = LLMGateway(SlowProvider(delay_s=2.0), timeout_s=0.2)
    agent = make_agent(gateway)
    outcome = agent.investigate(alert, enrichment, verdict_id="v1")
    assert outcome.verdict.disposition == Disposition.NEEDS_HUMAN
    assert outcome.error is not None and "timeout" in outcome.error.lower()


class InventingProvider:
    """Returns a report citing an IoC that enrichment never produced."""

    name = "inventing"

    def complete(self, prompt: str, *, alert_id: str) -> CompletionResult:
        report = {
            "alert_id": alert_id,
            "summary": "confident but fabricated",
            "ioc_values": ["9.9.9.9"],
            "severity_proposal": "critical",
            "recommended_actions": ["request_containment_approval"],
            "confidence": 0.99,
        }
        return CompletionResult(
            text=json.dumps(report), tokens_in=10, tokens_out=10, cost_usd=0.001, model=self.name
        )


def test_invented_ioc_report_is_discarded(pipeline: EnrichmentPipeline) -> None:
    alert, enrichment = escalated_alert(pipeline, "powershell.exe -enc SQBFAFgA observed")
    agent = make_agent(LLMGateway(InventingProvider()))  # type: ignore[arg-type]
    outcome = agent.investigate(alert, enrichment, verdict_id="v1")
    assert outcome.report is None
    assert outcome.verdict.disposition == Disposition.NEEDS_HUMAN
    assert outcome.error is not None and "absent from enrichment" in outcome.error


def test_service_creates_approval_request_not_execution(
    pipeline: EnrichmentPipeline,
) -> None:
    store = InMemoryStore()
    alert, enrichment = escalated_alert(
        pipeline,
        "beaconing to 185.220.101.7 at regular intervals",
        host="WS-1031",
        event_time=datetime(2026, 1, 14, 10, 0, tzinfo=UTC),
        dst_ip="185.220.101.7",
    )
    store.alerts[alert.id] = alert
    store.enrichments[alert.id] = enrichment
    service = InvestigationService(store, LLMGateway(FakeProvider()))
    outcome = service.process(alert.id)
    assert outcome.verdict.disposition == Disposition.MALICIOUS
    assert len(store.approvals) == 1
    approval = next(iter(store.approvals.values()))
    assert approval.action.value == "block_indicator"
    assert approval.target == "185.220.101.7"
    assert approval.status.value == "pending"  # a human still has to decide

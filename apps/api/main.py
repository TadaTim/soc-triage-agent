"""FastAPI service: alert intake webhook, verdict queries, containment
approval console API.

Deliberately absent: any route that *executes* a containment action.
Containment exists only as ApprovalRequest records that a human decides on;
execution (if any) happens in systems outside this codebase. A contract test
(tests/contract/test_contracts.py) enforces this over the live route table.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from apps.consumers.services import InMemoryStore, TriageOrchestrator
from packages.investigate.agent import InvestigationService
from packages.investigate.gateway import LLMGateway
from packages.investigate.providers import FakeProvider
from packages.schemas.models import (
    Alert,
    ApprovalRequest,
    ApprovalStatus,
    ContainmentAction,
)

app = FastAPI(title="SOC Triage Agent API", version="0.1.0")

# In production the API and consumers run as separate processes over
# Kafka/Postgres; here they share one in-process store so the whole system
# is demoable and testable from this single service.
_orchestrator = TriageOrchestrator.create()
_store: InMemoryStore = _orchestrator.store
_investigations = InvestigationService(
    _store, LLMGateway(FakeProvider()), metrics=_orchestrator.metrics
)
_orchestrator._investigate = _investigations  # wire the escalation path


class ApprovalCreate(BaseModel):
    action: ContainmentAction
    target: str
    justification: str
    requested_by: str
    report_id: str | None = None


class ApprovalDecision(BaseModel):
    decision: ApprovalStatus  # approved | rejected — a human's decision record
    decided_by: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/metrics")
def metrics() -> PlainTextResponse:
    """Prometheus exposition for the in-process pipeline metrics."""
    return PlainTextResponse(_orchestrator.metrics.render_prometheus())


@app.post("/v1/alerts")
def intake_alert(alert: Alert) -> dict[str, Any]:
    """Alert intake webhook: normalize, dedup, enrich, verdict (and
    investigate when the deterministic layer escalates)."""
    outcome = _orchestrator.handle_raw(alert.model_dump_json())
    verdict = _store.latest_verdict(alert.id)
    return {
        "alert_id": alert.id,
        "status": outcome.status,
        "disposition": verdict.disposition.value if verdict else None,
        "decided_by": verdict.decided_by.value if verdict else None,
        "dedup_count": _store.dedup_counts.get(alert.id, 1),
    }


@app.get("/v1/alerts/{alert_id}")
def get_alert(alert_id: str) -> dict[str, Any]:
    alert = _store.alerts.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    enrichment = _store.enrichments.get(alert_id)
    return {
        "alert": alert.model_dump(mode="json"),
        "dedup_count": _store.dedup_counts.get(alert_id, 1),
        "enrichment": enrichment.model_dump(mode="json") if enrichment else None,
    }


@app.get("/v1/verdicts/{alert_id}")
def get_verdicts(alert_id: str) -> dict[str, Any]:
    """Full verdict lineage for an alert, oldest first — re-opened verdicts
    appear as new entries with supersedes_id set."""
    verdicts = [v for v in _store.verdicts if v.alert_id == alert_id]
    return {"alert_id": alert_id, "verdicts": [v.model_dump(mode="json") for v in verdicts]}


@app.post("/v1/approvals")
def create_approval(body: ApprovalCreate) -> dict[str, Any]:
    """Create a containment APPROVAL REQUEST. This records intent for a
    human to decide; it does not (and cannot) execute the action."""
    approval = ApprovalRequest(
        id=f"ap-{len(_store.approvals) + 1:04d}",
        action=body.action,
        target=body.target,
        justification=body.justification,
        requested_by=body.requested_by,
        report_id=body.report_id,
        created_at=datetime.now(UTC),
    )
    _store.approvals[approval.id] = approval
    return approval.model_dump(mode="json")


@app.get("/v1/approvals")
def list_approvals() -> dict[str, Any]:
    return {"approvals": [a.model_dump(mode="json") for a in _store.approvals.values()]}


@app.get("/v1/approvals/{approval_id}")
def get_approval(approval_id: str) -> dict[str, Any]:
    approval = _store.approvals.get(approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="approval not found")
    return approval.model_dump(mode="json")


@app.post("/v1/approvals/{approval_id}/decision")
def decide_approval(approval_id: str, body: ApprovalDecision) -> dict[str, Any]:
    """Record a human's decision on an approval request. Recording a
    decision is all this API does — execution is out of scope by design."""
    approval = _store.approvals.get(approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="approval not found")
    if body.decision not in (ApprovalStatus.APPROVED, ApprovalStatus.REJECTED):
        raise HTTPException(status_code=422, detail="decision must be approved or rejected")
    updated = approval.model_copy(
        update={
            "status": body.decision,
            "decided_by": body.decided_by,
            "decided_at": datetime.now(UTC),
        }
    )
    _store.approvals[approval_id] = updated
    return updated.model_dump(mode="json")

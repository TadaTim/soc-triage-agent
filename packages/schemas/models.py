"""Shared Pydantic v2 contracts for the SOC triage pipeline.

Design rules encoded here (not in documentation):
- An InvestigationReport can only cite IoCs that exist in an EnrichmentResult.
  The model cannot invent indicators; `validate_iocs` is the enforcement point.
- Containment actions exist ONLY as ApprovalRequest objects. There is no
  "execute containment" shape anywhere in this contract layer, and the API
  (apps/api) mirrors that: it can record approval *decisions*, never execute.
- Verdicts are append-only. A late/out-of-order event produces a NEW verdict
  whose `supersedes_id` points at the verdict it replaces — history is never
  silently rewritten.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Disposition(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    NEEDS_HUMAN = "needs_human"


class DecidedBy(StrEnum):
    DETERMINISTIC = "deterministic"
    LLM = "llm"
    HUMAN = "human"


class IoCType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    EMAIL = "email"
    FILE = "file"
    CVE = "cve"


class ContainmentAction(StrEnum):
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    BLOCK_INDICATOR = "block_indicator"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class RecommendedAction(StrEnum):
    NONE = "none"
    MONITOR = "monitor"
    COLLECT_FORENSICS = "collect_forensics"
    REQUEST_CONTAINMENT_APPROVAL = "request_containment_approval"
    ESCALATE_TO_IR = "escalate_to_ir"


class Alert(BaseModel):
    """A normalized alert. `event_time` (sensor clock) and `ingest_time`
    (our clock) are distinct fields because sensor clock skew is a
    first-class concern: late events re-open verdicts explicitly."""

    model_config = ConfigDict(frozen=True)

    id: str
    source: str
    sensor_id: str
    severity: Severity
    title: str
    event_time: datetime
    ingest_time: datetime
    payload: str
    payload_hash: str = ""
    src_ip: str | None = None
    dst_ip: str | None = None
    host: str | None = None
    user: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _fill_payload_hash(cls, data: Any) -> Any:
        if isinstance(data, dict) and not data.get("payload_hash") and "payload" in data:
            data = dict(data)
            data["payload_hash"] = hashlib.sha256(str(data["payload"]).encode()).hexdigest()
        return data


class IoC(BaseModel):
    """An extracted indicator. `value` is the normalized form; `raw` is the
    exact substring of the payload at [start, end) (offsets are into the
    ORIGINAL payload, even when the raw form is defanged, e.g. `hxxp://`
    or `1.2.3[.]4`)."""

    model_config = ConfigDict(frozen=True)

    type: IoCType
    value: str
    raw: str
    start: int = Field(ge=0)
    end: int = Field(gt=0)

    @model_validator(mode="after")
    def _check_span(self) -> Self:
        if self.end <= self.start:
            raise ValueError(f"invalid IoC span [{self.start}, {self.end})")
        return self


class EnrichmentRecord(BaseModel):
    """One typed enrichment fact, with provenance and confidence."""

    model_config = ConfigDict(frozen=True)

    kind: str  # intel_hit | asset_context | allowlist_match | reserved_range |
    #            engagement_window | behavioral_signal | history | degraded_note
    source: str
    confidence: float = Field(ge=0.0, le=1.0)
    ioc_value: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class EnrichmentResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    alert_id: str
    iocs: list[IoC] = Field(default_factory=list)
    records: list[EnrichmentRecord] = Field(default_factory=list)
    score: float = 0.0
    signals: list[str] = Field(default_factory=list)
    degraded: bool = False  # True in storm mode (optional lookups shed)

    def ioc_values(self) -> set[str]:
        return {ioc.value for ioc in self.iocs}


class InvestigationReport(BaseModel):
    """LLM-produced investigation output. Every value in `ioc_values` MUST
    resolve to an IoC in the alert's EnrichmentResult — see validate_iocs."""

    model_config = ConfigDict(frozen=True)

    alert_id: str
    summary: str
    ioc_values: list[str] = Field(default_factory=list)
    severity_proposal: Severity
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)

    def validate_iocs(self, enrichment: EnrichmentResult) -> None:
        """Raise ValueError if the report cites an IoC the enrichment layer
        never produced. This is the anti-hallucination gate: a report that
        fails here is discarded and the alert goes to a human."""
        known = enrichment.ioc_values()
        unknown = [v for v in self.ioc_values if v not in known]
        if unknown:
            raise ValueError(f"InvestigationReport cites IoCs absent from enrichment: {unknown}")


class Verdict(BaseModel):
    """Append-only decision record. Re-opened verdicts supersede explicitly."""

    model_config = ConfigDict(frozen=True)

    id: str
    alert_id: str
    disposition: Disposition
    decided_by: DecidedBy
    rationale: str
    score: float = 0.0
    lineage: list[str] = Field(default_factory=list)  # enrichment/record/report IDs
    supersedes_id: str | None = None
    created_at: datetime


class ApprovalRequest(BaseModel):
    """The ONLY representation of a containment action in this system.

    A human records a decision (approved/rejected). Nothing in this codebase
    executes the action; execution belongs to external response tooling that
    consumes approved requests. There is intentionally no `execute` field,
    method, or API route.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    action: ContainmentAction
    target: str
    justification: str
    requested_by: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    report_id: str | None = None
    decided_by: str | None = None
    decided_at: datetime | None = None
    created_at: datetime


class DeadLetterEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    topic: str
    payload: str
    error_history: list[str] = Field(default_factory=list)
    attempts: int = 0
    created_at: datetime

"""Deterministic enrichment + scoring + verdict decision.

This is the layer that closes the overwhelming majority of alerts with NO
LLM involvement. The scoring model is deliberately legible — a weighted sum
of named signals — because an analyst must be able to replay any verdict:

- A high-confidence threat-intel hit is decisive on its own (hard rule).
- Behavioral patterns (download cradles, encoded commands, credential
  tooling) carry heavy weight because they describe *actions*, not words.
- Allowlist / engagement-window / documentation-range matches subtract,
  because context is what separates a pentest from an incident.
- Anything that lands in the middle band escalates. The deterministic layer
  is allowed to say "I don't know" — it is never allowed to guess benign.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from packages.enrich.extract import extract_iocs
from packages.enrich.intel import AssetInventory, ThreatIntel, ip_class
from packages.schemas.models import (
    Alert,
    DecidedBy,
    Disposition,
    EnrichmentRecord,
    EnrichmentResult,
    IoCType,
    Severity,
    Verdict,
)

SEVERITY_BASE: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 5.0,
    Severity.MEDIUM: 15.0,
    Severity.HIGH: 30.0,
    Severity.CRITICAL: 45.0,
}

MALICIOUS_THRESHOLD = 80.0
BENIGN_THRESHOLD = 20.0
INTEL_HARD_CONFIDENCE = 0.85

# (signal name, pattern, points) — patterns match the defanged-normalized,
# lowercased payload.
BEHAVIORAL_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    (
        "download_cradle",
        re.compile(r"(downloadstring|downloadfile|invoke-expression|\biex\b|frombase64string)"),
        60.0,
    ),
    (
        "credential_tooling",
        re.compile(r"(sekurlsa|logonpasswords|mimikatz\.exe|lsass\.dmp)"),
        60.0,
    ),
    (
        "encoded_command",
        re.compile(r"powershell(\.exe)?\s+-(enc|encodedcommand)\b"),
        45.0,
    ),
]

ASSET_BONUS = {"high": 10.0, "critical": 10.0}


def _looks_dga(domain: str) -> bool:
    """Cheap DGA heuristic: a long label with a high digit ratio reads as
    algorithm-generated. Deliberately conservative (digit ratio, not raw
    entropy) so ordinary long hostnames never trip it."""
    for label in domain.split("."):
        if len(label) >= 10:
            digit_ratio = sum(c.isdigit() for c in label) / len(label)
            if digit_ratio >= 0.2:
                return True
    return False


@dataclass(frozen=True)
class Decision:
    """Outcome of the deterministic layer: either a final verdict or an
    escalation (verdict is None) — never both, never neither."""

    verdict: Verdict | None
    escalate: bool
    reason: str


class EnrichmentPipeline:
    def __init__(self, intel: ThreatIntel, assets: AssetInventory) -> None:
        self._intel = intel
        self._assets = assets

    @classmethod
    def from_data_dir(cls) -> EnrichmentPipeline:
        return cls(ThreatIntel.from_data_dir(), AssetInventory.from_data_dir())

    # ------------------------------------------------------------- enrich --

    def enrich(self, alert: Alert, *, storm_mode: bool = False) -> EnrichmentResult:
        iocs = extract_iocs(alert.payload)
        records: list[EnrichmentRecord] = []
        signals: list[str] = []
        score = SEVERITY_BASE[alert.severity]
        hard_malicious = False

        # --- threat-intel lookups (structured fields + extracted IoCs) ---
        intel_checked: set[str] = set()
        candidates = [v for v in (alert.src_ip, alert.dst_ip) if v]
        candidates += [ioc.value for ioc in iocs]
        for value in candidates:
            if value in intel_checked:
                continue
            intel_checked.add(value)
            hit = self._intel.lookup(value)
            if hit is not None:
                records.append(
                    EnrichmentRecord(
                        kind="intel_hit",
                        source=hit.source,
                        confidence=hit.confidence,
                        ioc_value=value,
                        detail={"matched": hit.matched_value, "tags": hit.tags},
                    )
                )
                if hit.confidence >= INTEL_HARD_CONFIDENCE:
                    hard_malicious = True
                    signals.append(f"intel_hit:{hit.matched_value}")
                else:
                    score += 40.0
                    signals.append(f"intel_hit_medium:{hit.matched_value}")

        if hard_malicious:
            score += 100.0

        # --- behavioral signals -------------------------------------------
        text = alert.payload.lower()
        behavioral_points = 0.0
        for name, pattern, points in BEHAVIORAL_PATTERNS:
            if pattern.search(text):
                behavioral_points += points
                signals.append(f"behavioral:{name}")
                records.append(
                    EnrichmentRecord(
                        kind="behavioral_signal",
                        source="enrich.rules",
                        confidence=0.8,
                        detail={"signal": name, "points": points},
                    )
                )
        score += behavioral_points

        # --- external unknown endpoints (src/dst fields + URL hosts) -----
        external_seen = False
        url_hosts = {
            ioc.value
            for ioc in iocs
            if ioc.type in (IoCType.IPV4, IoCType.DOMAIN)
            and any(
                u.value.split("://", 1)[-1].startswith(ioc.value)
                for u in iocs
                if u.type == IoCType.URL
            )
        }
        for value in {v for v in (alert.src_ip, alert.dst_ip) if v} | url_hosts:
            if self._intel.lookup(value) is not None:
                continue
            if self._intel.is_scanner(value) or self._intel.is_office_egress(value):
                continue
            is_ip = all(ch.isdigit() or ch == "." for ch in value)
            if (is_ip and ip_class(value) == "global") or (
                not is_ip and not self._intel.is_trusted_domain(value)
            ):
                external_seen = True
        if external_seen:
            score += 15.0
            signals.append("external_unknown")

        # --- unknown file hash ---------------------------------------------
        for ioc in iocs:
            if ioc.type == IoCType.SHA256 and self._intel.lookup(ioc.value) is None:
                if not self._intel.is_known_good_hash(ioc.value):
                    score += 15.0
                    signals.append("unknown_hash")
                    records.append(
                        EnrichmentRecord(
                            kind="history",
                            source="enrich.rules",
                            confidence=0.5,
                            ioc_value=ioc.value,
                            detail={"note": "hash in no feed and no known-good list"},
                        )
                    )
                break

        # --- DGA-shaped domains --------------------------------------------
        for ioc in iocs:
            if (
                ioc.type == IoCType.DOMAIN
                and self._intel.lookup(ioc.value) is None
                and not self._intel.is_trusted_domain(ioc.value)
                and _looks_dga(ioc.value)
            ):
                score += 25.0
                signals.append(f"dga_like:{ioc.value}")
                break

        # --- context that subtracts ----------------------------------------
        if (alert.src_ip and self._intel.is_scanner(alert.src_ip)) or (
            alert.src_ip and self._intel.is_office_egress(alert.src_ip)
        ):
            score -= 50.0
            signals.append("allowlisted_source")
            records.append(
                EnrichmentRecord(
                    kind="allowlist_match",
                    source="allowlist",
                    confidence=0.95,
                    ioc_value=alert.src_ip,
                    detail={"note": "scanner or branch-office egress"},
                )
            )
        if any(
            ioc.type == IoCType.DOMAIN and self._intel.is_trusted_domain(ioc.value) for ioc in iocs
        ):
            score -= 50.0
            signals.append("trusted_domain")

        engagement = self._intel.engagement_for(alert.host, alert.event_time.date())
        if engagement is not None:
            score -= 80.0
            signals.append(f"engagement_window:{engagement['ticket']}")
            records.append(
                EnrichmentRecord(
                    kind="engagement_window",
                    source="pentest-calendar",
                    confidence=1.0,
                    detail={"ticket": engagement["ticket"]},
                )
            )

        if any(ioc.type == IoCType.IPV4 and ip_class(ioc.value) == "documentation" for ioc in iocs):
            score -= 20.0
            signals.append("documentation_range_indicator")
            records.append(
                EnrichmentRecord(
                    kind="reserved_range",
                    source="enrich.rules",
                    confidence=1.0,
                    detail={"note": "RFC 5737 documentation range; not routable"},
                )
            )

        # --- asset context --------------------------------------------------
        asset = self._assets.lookup(alert.host)
        if asset is not None:
            records.append(
                EnrichmentRecord(
                    kind="asset_context",
                    source="asset-inventory",
                    confidence=1.0,
                    detail={"criticality": asset.criticality, "owner": asset.owner},
                )
            )
            if asset.criticality in ASSET_BONUS and score > SEVERITY_BASE[alert.severity]:
                score += ASSET_BONUS[asset.criticality]
                signals.append(f"asset_criticality:{asset.criticality}")

        if storm_mode:
            records.append(
                EnrichmentRecord(
                    kind="degraded_note",
                    source="enrich.pipeline",
                    confidence=1.0,
                    detail={"note": "storm mode: optional lookups shed, cache-only intel"},
                )
            )

        return EnrichmentResult(
            alert_id=alert.id,
            iocs=iocs,
            records=records,
            score=score,
            signals=signals,
            degraded=storm_mode,
        )

    # ------------------------------------------------------------- decide --

    def decide(self, alert: Alert, result: EnrichmentResult, *, verdict_id: str) -> Decision:
        lineage = [f"enrichment:{alert.id}", *result.signals]
        if result.score >= MALICIOUS_THRESHOLD:
            verdict = Verdict(
                id=verdict_id,
                alert_id=alert.id,
                disposition=Disposition.MALICIOUS,
                decided_by=DecidedBy.DETERMINISTIC,
                rationale=f"score {result.score:.0f} >= {MALICIOUS_THRESHOLD:.0f}: "
                + ", ".join(result.signals),
                score=result.score,
                lineage=lineage,
                created_at=alert.ingest_time,
            )
            return Decision(verdict=verdict, escalate=False, reason="malicious_threshold")
        if result.score <= BENIGN_THRESHOLD:
            verdict = Verdict(
                id=verdict_id,
                alert_id=alert.id,
                disposition=Disposition.BENIGN,
                decided_by=DecidedBy.DETERMINISTIC,
                rationale=f"score {result.score:.0f} <= {BENIGN_THRESHOLD:.0f}: "
                + (", ".join(result.signals) or "no adverse signals"),
                score=result.score,
                lineage=lineage,
                created_at=alert.ingest_time,
            )
            return Decision(verdict=verdict, escalate=False, reason="benign_threshold")
        return Decision(
            verdict=None,
            escalate=True,
            reason=f"score {result.score:.0f} in escalation band "
            f"({BENIGN_THRESHOLD:.0f}, {MALICIOUS_THRESHOLD:.0f})",
        )

"""Eval scoring.

Gate philosophy (asymmetric costs): the catastrophic error is closing a
real attack as benign, so benign-closure precision is gated at 0.99 while
other metrics get realistic thresholds. Malicious recall counts any outcome
that does NOT close the alert as benign — an escalation is a safe outcome
for a real attack, a benign closure is not.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AlertOutcome:
    alert_id: str
    expected: str  # benign | malicious | needs_human
    final_disposition: str  # benign | suspicious | malicious | needs_human
    decided_by: str  # deterministic | llm | human
    cost_usd: float
    extracted_iocs: set[tuple[str, str]] = field(default_factory=set)
    expected_iocs: set[tuple[str, str]] = field(default_factory=set)


@dataclass
class Scorecard:
    total: int
    benign_closure_precision: float
    malicious_recall: float
    ioc_precision: float
    ioc_recall: float
    ioc_f1: float
    escalation_rate: float
    deterministic_rate: float
    blended_cost_per_alert: float
    exact_match_accuracy: float
    gates: dict[str, bool] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return all(self.gates.values())

    def render(self) -> str:
        def mark(ok: bool) -> str:
            return "PASS" if ok else "FAIL"

        lines = [
            "=" * 64,
            "SOC TRIAGE EVAL SCORECARD",
            "=" * 64,
            f"alerts scored:                {self.total}",
            f"benign-closure precision:     {self.benign_closure_precision:.4f}  "
            f"[{mark(self.gates['benign_closure_precision'])}] gate >= 0.99",
            f"malicious recall:             {self.malicious_recall:.4f}  "
            f"[{mark(self.gates['malicious_recall'])}] gate >= 0.95",
            f"IoC extraction F1:            {self.ioc_f1:.4f}  "
            f"[{mark(self.gates['ioc_f1'])}] gate >= 0.95 "
            f"(P {self.ioc_precision:.3f} / R {self.ioc_recall:.3f})",
            f"deterministic resolution:     {self.deterministic_rate:.4f}  "
            f"[{mark(self.gates['deterministic_rate'])}] gate >= 0.95 "
            f"(escalation {self.escalation_rate:.4f})",
            f"blended cost per alert:       ${self.blended_cost_per_alert:.5f}  "
            f"[{mark(self.gates['blended_cost'])}] gate <= $0.015",
            f"exact-match accuracy:         {self.exact_match_accuracy:.4f}  (reported)",
            "=" * 64,
            "OVERALL: " + ("PASS" if self.passed else "FAIL"),
        ]
        return "\n".join(lines)


def score(outcomes: list[AlertOutcome]) -> Scorecard:
    total = len(outcomes)

    benign_closed = [o for o in outcomes if o.final_disposition == "benign"]
    truly_benign = [o for o in benign_closed if o.expected == "benign"]
    precision = len(truly_benign) / len(benign_closed) if benign_closed else 1.0

    malicious = [o for o in outcomes if o.expected == "malicious"]
    recalled = [o for o in malicious if o.final_disposition != "benign"]
    recall = len(recalled) / len(malicious) if malicious else 1.0

    tp = sum(len(o.extracted_iocs & o.expected_iocs) for o in outcomes)
    fp = sum(len(o.extracted_iocs - o.expected_iocs) for o in outcomes)
    fn = sum(len(o.expected_iocs - o.extracted_iocs) for o in outcomes)
    ioc_p = tp / (tp + fp) if tp + fp else 1.0
    ioc_r = tp / (tp + fn) if tp + fn else 1.0
    ioc_f1 = 2 * ioc_p * ioc_r / (ioc_p + ioc_r) if ioc_p + ioc_r else 0.0

    deterministic = sum(1 for o in outcomes if o.decided_by == "deterministic")
    det_rate = deterministic / total if total else 0.0
    blended = sum(o.cost_usd for o in outcomes) / total if total else 0.0
    exact = sum(1 for o in outcomes if o.final_disposition == o.expected) / total if total else 0.0

    gates = {
        "benign_closure_precision": precision >= 0.99,
        "malicious_recall": recall >= 0.95,
        "ioc_f1": ioc_f1 >= 0.95,
        "deterministic_rate": det_rate >= 0.95,
        "blended_cost": blended <= 0.015,
    }
    return Scorecard(
        total=total,
        benign_closure_precision=precision,
        malicious_recall=recall,
        ioc_precision=ioc_p,
        ioc_recall=ioc_r,
        ioc_f1=ioc_f1,
        escalation_rate=1.0 - det_rate,
        deterministic_rate=det_rate,
        blended_cost_per_alert=blended,
        exact_match_accuracy=exact,
        gates=gates,
    )

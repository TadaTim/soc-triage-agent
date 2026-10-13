"""Metrics registry with Prometheus text export.

A deliberately small in-house registry (counters / gauges / histograms)
so the services have zero hard dependency on a metrics backend in tests
and local runs; the exported text format is what Prometheus/Grafana
consume in deployment.

Metric inventory (names are the contract the Grafana dashboard and alert
rules are written against):
- soc_alerts_ingested_total / soc_alerts_duplicated_total  (dedup ratio)
- soc_verdicts_total{stage,disposition}                     (verdict volume)
- soc_verdict_latency_seconds{stage}                        (stage latency)
- soc_escalations_total                                     (escalation rate)
- soc_llm_spend_usd_total                                   (LLM spend)
- soc_consumer_lag / soc_storm_mode / soc_dlq_depth         (pipeline health)
"""

from __future__ import annotations

from dataclasses import dataclass, field

HISTOGRAM_BUCKETS = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 90.0)


def _label_str(labels: dict[str, str]) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    return "{" + inner + "}"


@dataclass
class Metrics:
    counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = field(default_factory=dict)
    gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = field(default_factory=dict)
    hist_counts: dict[tuple[str, tuple[tuple[str, str], ...]], list[int]] = field(
        default_factory=dict
    )
    hist_sums: dict[tuple[str, tuple[tuple[str, str], ...]], float] = field(default_factory=dict)

    @staticmethod
    def _key(name: str, labels: dict[str, str] | None) -> tuple[str, tuple[tuple[str, str], ...]]:
        return name, tuple(sorted((labels or {}).items()))

    def inc(self, name: str, labels: dict[str, str] | None = None, amount: float = 1.0) -> None:
        key = self._key(name, labels)
        self.counters[key] = self.counters.get(key, 0.0) + amount

    def set_gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        self.gauges[self._key(name, labels)] = value

    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = self._key(name, labels)
        counts = self.hist_counts.setdefault(key, [0] * (len(HISTOGRAM_BUCKETS) + 1))
        for i, bound in enumerate(HISTOGRAM_BUCKETS):
            if value <= bound:
                counts[i] += 1
        counts[-1] += 1  # +Inf bucket = total count
        self.hist_sums[key] = self.hist_sums.get(key, 0.0) + value

    def counter_value(self, name: str, labels: dict[str, str] | None = None) -> float:
        return self.counters.get(self._key(name, labels), 0.0)

    def render_prometheus(self) -> str:
        lines: list[str] = []
        for (name, labels), value in sorted(self.counters.items()):
            lines.append(f"{name}{_label_str(dict(labels))} {value}")
        for (name, labels), value in sorted(self.gauges.items()):
            lines.append(f"{name}{_label_str(dict(labels))} {value}")
        for (name, labels), counts in sorted(self.hist_counts.items()):
            label_dict = dict(labels)
            for bound, count in zip((*HISTOGRAM_BUCKETS, float("inf")), counts, strict=True):
                bucket_labels = {
                    **label_dict,
                    "le": "+Inf" if bound == float("inf") else str(bound),
                }
                lines.append(f"{name}_bucket{_label_str(bucket_labels)} {count}")
            lines.append(f"{name}_sum{_label_str(label_dict)} {self.hist_sums[(name, labels)]}")
            lines.append(f"{name}_count{_label_str(label_dict)} {counts[-1]}")
        return "\n".join(lines) + "\n"

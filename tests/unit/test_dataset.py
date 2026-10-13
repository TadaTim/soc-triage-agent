"""Golden dataset integrity (Stage 3 validation)."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

DATASET = Path("packages/evals/dataset.jsonl")


def load() -> list[dict]:
    return [json.loads(line) for line in DATASET.read_text().splitlines() if line.strip()]


def test_dataset_loads_with_label_counts() -> None:
    records = load()
    assert len(records) == 500
    labels = Counter(r["expected_disposition"] for r in records)
    assert labels["benign"] == 315
    assert labels["malicious"] == 165
    assert labels["needs_human"] == 20
    print(f"label counts: {dict(labels)}")


def test_adversarial_cases_present() -> None:
    records = load()
    adversarial = [r for r in records if r["adversarial"]]
    assert len(adversarial) >= 40, f"only {len(adversarial)} adversarial cases"
    adv_labels = Counter(r["expected_disposition"] for r in adversarial)
    # Both directions: benign-looking attacks and scary-looking benign noise.
    assert adv_labels["malicious"] >= 15
    assert adv_labels["benign"] >= 40


def test_every_record_has_expected_iocs_and_valid_alert_shape() -> None:
    from packages.schemas.models import Alert

    for rec in load():
        alert = Alert(
            **{
                k: rec[k]
                for k in (
                    "id",
                    "source",
                    "sensor_id",
                    "severity",
                    "title",
                    "event_time",
                    "ingest_time",
                    "payload",
                    "src_ip",
                    "dst_ip",
                    "host",
                    "user",
                )
            }
        )
        assert alert.payload_hash  # computed by the model validator
        assert rec["expected_iocs"], f"{rec['id']} has no expected IoCs"
        for ioc in rec["expected_iocs"]:
            assert ioc["value"].lower() in alert.payload.lower().replace("[.]", ".").replace(
                "hxxp", "http"
            ), f"{rec['id']}: expected IoC {ioc['value']} not findable in payload"

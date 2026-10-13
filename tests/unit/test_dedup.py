"""Dedup key stability and correlation-window behavior."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from packages.enrich.dedup import DedupTracker, compute_dedup_key
from packages.schemas.models import Alert, Severity

T0 = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)


def make(event_time: datetime, **kw: object) -> Alert:
    fields: dict[str, object] = {
        "id": "x",
        "source": "firewall",
        "sensor_id": "fw-1",
        "severity": Severity.MEDIUM,
        "title": "Beaconing",
        "event_time": event_time,
        "ingest_time": event_time,
        "payload": "p",
        "dst_ip": "185.220.101.7",
        "host": "WS-1001",
    }
    fields.update(kw)
    return Alert(**fields)  # type: ignore[arg-type]


def test_key_stable_within_window_bucket() -> None:
    a = make(T0)
    b = make(T0 + timedelta(minutes=3), id="y")
    assert compute_dedup_key(a) == compute_dedup_key(b)


def test_key_changes_across_buckets_and_fields() -> None:
    a = make(T0)
    assert compute_dedup_key(a) != compute_dedup_key(make(T0 + timedelta(minutes=30)))
    assert compute_dedup_key(a) != compute_dedup_key(make(T0, title="Different"))
    assert compute_dedup_key(a) != compute_dedup_key(make(T0, dst_ip="185.220.101.8"))


def test_tracker_counts_duplicates_and_expires() -> None:
    tracker = DedupTracker()
    dup, canonical, count = tracker.check(make(T0, id="first"))
    assert (dup, canonical, count) == (False, "first", 1)
    dup, canonical, count = tracker.check(make(T0 + timedelta(minutes=2), id="second"))
    assert (dup, canonical, count) == (True, "first", 2)
    # An hour later the same shape is a NEW alert, not a duplicate.
    dup, canonical, count = tracker.check(make(T0 + timedelta(hours=1), id="third"))
    assert (dup, canonical, count) == (False, "third", 1)

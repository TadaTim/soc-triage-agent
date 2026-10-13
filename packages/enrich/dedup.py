"""Deduplication / correlation.

During a real incident one root cause produces a storm of near-identical
alerts. The dedup key collapses them BEFORE any expensive work (and long
before any LLM spend is authorized): duplicates increment a counter on the
original alert instead of creating new work.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta

from packages.schemas.models import Alert

WINDOW_SECONDS = 600  # 10-minute correlation window


def compute_dedup_key(alert: Alert) -> str:
    """Stable key over the alert's identity fields + a time bucket.

    The bucket is derived from event_time (floored to the window), so the
    same sensor firing the same alert inside the window maps to one key even
    as payloads jitter slightly.
    """
    bucket = int(alert.event_time.timestamp()) // WINDOW_SECONDS
    parts = [
        alert.source,
        alert.sensor_id,
        alert.title.strip().lower(),
        alert.src_ip or "",
        alert.dst_ip or "",
        alert.host or "",
        str(bucket),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


@dataclass
class _Entry:
    alert_id: str
    first_event_time: datetime
    count: int = 1


class DedupTracker:
    """In-memory correlation tracker (Redis-backed in production; the
    interface is the point — check() is atomic from the caller's view)."""

    def __init__(self, window_seconds: int = WINDOW_SECONDS) -> None:
        self._window = timedelta(seconds=window_seconds)
        self._entries: dict[str, _Entry] = {}

    def check(self, alert: Alert) -> tuple[bool, str, int]:
        """Return (is_duplicate, canonical_alert_id, dedup_count).

        A duplicate returns the FIRST alert's id and the incremented count;
        the caller increments the stored alert's counter and drops the copy.
        """
        key = compute_dedup_key(alert)
        entry = self._entries.get(key)
        if entry is not None and alert.event_time - entry.first_event_time <= self._window:
            entry.count += 1
            return True, entry.alert_id, entry.count
        self._entries[key] = _Entry(alert_id=alert.id, first_event_time=alert.event_time)
        return False, alert.id, 1

"""Structured JSON logging.

Rules:
- Every record carries alert_id + trace_id when the caller has them.
- Raw alert payloads are NEVER logged. Payloads live in the alerts table;
  logs carry the payload HASH so a log line can be correlated with a
  stored alert without leaking telemetry content into log streams.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for field_name in ("alert_id", "trace_id", "stage", "disposition"):
            value = getattr(record, field_name, None)
            if value is not None:
                entry[field_name] = value
        return json.dumps(entry, sort_keys=True)


def payload_hash(payload: str) -> str:
    """The only representation of a payload allowed in logs."""
    return hashlib.sha256(payload.encode()).hexdigest()


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger

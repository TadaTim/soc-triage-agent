"""Initial schema: alerts, enrichments, investigations, verdicts (append-only),
approvals, threat_intel_cache, dead_letters.

Deploy order: this migration is self-contained and safe to run before any
service deploy. Downgrade drops everything (dev/test only).
"""

from __future__ import annotations

from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE alerts (
            id            TEXT PRIMARY KEY,
            dedup_key     TEXT NOT NULL,
            source        TEXT NOT NULL,
            sensor_id     TEXT NOT NULL,
            severity      TEXT NOT NULL,
            title         TEXT NOT NULL,
            event_time    TIMESTAMPTZ NOT NULL,
            ingest_time   TIMESTAMPTZ NOT NULL,
            payload       TEXT NOT NULL,
            payload_hash  TEXT NOT NULL,
            src_ip        TEXT,
            dst_ip        TEXT,
            host          TEXT,
            "user"        TEXT
        );
        CREATE INDEX ix_alerts_dedup_key ON alerts (dedup_key);
        CREATE INDEX ix_alerts_event_time ON alerts (event_time);

        CREATE TABLE enrichments (
            id          TEXT PRIMARY KEY,
            alert_id    TEXT NOT NULL REFERENCES alerts (id),
            result      JSONB NOT NULL,
            created_at  TIMESTAMPTZ NOT NULL
        );

        CREATE TABLE investigations (
            id          TEXT PRIMARY KEY,
            alert_id    TEXT NOT NULL REFERENCES alerts (id),
            report      JSONB,
            tool_calls  INTEGER NOT NULL DEFAULT 0,
            cost_usd    NUMERIC(10, 6) NOT NULL DEFAULT 0,
            created_at  TIMESTAMPTZ NOT NULL
        );

        -- Append-only: a re-opened verdict is a new row with supersedes_id set.
        CREATE TABLE verdicts (
            id            TEXT PRIMARY KEY,
            alert_id      TEXT NOT NULL REFERENCES alerts (id),
            disposition   TEXT NOT NULL,
            decided_by    TEXT NOT NULL,
            rationale     TEXT NOT NULL,
            score         DOUBLE PRECISION NOT NULL DEFAULT 0,
            lineage       JSONB NOT NULL DEFAULT '[]',
            supersedes_id TEXT REFERENCES verdicts (id),
            created_at    TIMESTAMPTZ NOT NULL
        );
        CREATE INDEX ix_verdicts_alert ON verdicts (alert_id, created_at);

        -- Containment lives here ONLY as human-decided approval requests.
        CREATE TABLE approvals (
            id            TEXT PRIMARY KEY,
            action        TEXT NOT NULL,
            target        TEXT NOT NULL,
            justification TEXT NOT NULL,
            requested_by  TEXT NOT NULL,
            status        TEXT NOT NULL DEFAULT 'pending',
            report_id     TEXT,
            decided_by    TEXT,
            decided_at    TIMESTAMPTZ,
            created_at    TIMESTAMPTZ NOT NULL
        );

        CREATE TABLE threat_intel_cache (
            value       TEXT PRIMARY KEY,
            record      JSONB NOT NULL,
            expires_at  TIMESTAMPTZ NOT NULL
        );

        CREATE TABLE dead_letters (
            id            TEXT PRIMARY KEY,
            topic         TEXT NOT NULL,
            payload       TEXT NOT NULL,
            error_history JSONB NOT NULL DEFAULT '[]',
            attempts      INTEGER NOT NULL DEFAULT 0,
            created_at    TIMESTAMPTZ NOT NULL
        );
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE IF EXISTS dead_letters;
        DROP TABLE IF EXISTS threat_intel_cache;
        DROP TABLE IF EXISTS approvals;
        DROP TABLE IF EXISTS verdicts;
        DROP TABLE IF EXISTS investigations;
        DROP TABLE IF EXISTS enrichments;
        DROP TABLE IF EXISTS alerts;
        """
    )

"""CONTRACT step for alerts.dedup_count: backfill, then enforce NOT NULL.

Safe ONLY after 0002 and after all writers populate dedup_count (see the
deploy order in 0002). Downgrade returns the column to nullable.
"""

from __future__ import annotations

from alembic import op

revision: str = "0003_dedup_contract"
down_revision: str | None = "0002_dedup_expand"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute("UPDATE alerts SET dedup_count = 1 WHERE dedup_count IS NULL;")
    op.execute("ALTER TABLE alerts ALTER COLUMN dedup_count SET DEFAULT 1;")
    op.execute("ALTER TABLE alerts ALTER COLUMN dedup_count SET NOT NULL;")


def downgrade() -> None:
    op.execute("ALTER TABLE alerts ALTER COLUMN dedup_count DROP NOT NULL;")
    op.execute("ALTER TABLE alerts ALTER COLUMN dedup_count DROP DEFAULT;")

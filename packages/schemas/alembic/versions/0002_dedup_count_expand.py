"""EXPAND step for alerts.dedup_count: add the column NULLABLE with no default.

Deploy order (expand/contract):
  1. Deploy THIS migration (column exists, nullable, old code unaffected).
  2. Deploy the code that writes dedup_count.
  3. Deploy 0003 (backfill + NOT NULL) only after step 2 is fully rolled out.
"""

from __future__ import annotations

from alembic import op

revision: str = "0002_dedup_expand"
down_revision: str | None = "0001_initial"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE alerts ADD COLUMN dedup_count INTEGER;")


def downgrade() -> None:
    op.execute("ALTER TABLE alerts DROP COLUMN dedup_count;")

"""Guard-tool tests: migration safety + dataset changelog rules."""

from __future__ import annotations

from pathlib import Path

from tools.check_dataset_changelog import violations
from tools.check_migrations import check_file


def test_real_migrations_pass_safety_check() -> None:
    versions = Path("packages/schemas/alembic/versions")
    problems: list[str] = []
    for path in sorted(versions.glob("*.py")):
        problems.extend(check_file(path))
    assert problems == []


def test_same_migration_add_and_not_null_fails(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text(
        "def upgrade() -> None:\n"
        '    op.execute("ALTER TABLE t ADD COLUMN c INTEGER;")\n'
        '    op.execute("ALTER TABLE t ALTER COLUMN c SET NOT NULL;")\n'
        "\n\ndef downgrade() -> None:\n    pass\n"
    )
    assert check_file(bad)


def test_unreviewed_drop_fails_but_reviewed_drop_passes(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text(
        'def upgrade() -> None:\n    op.execute("DROP TABLE t;")\n\n'
        "def downgrade() -> None:\n    pass\n"
    )
    assert check_file(bad)
    reviewed = tmp_path / "ok.py"
    reviewed.write_text(
        "# REVIEWED-DESTRUCTIVE: table replaced by v2 design, data migrated in 0007\n"
        'def upgrade() -> None:\n    op.execute("DROP TABLE t;")\n\n'
        "def downgrade() -> None:\n    pass\n"
    )
    assert check_file(reviewed) == []


def test_dataset_changelog_rule() -> None:
    assert violations(["packages/evals/dataset.jsonl"])  # missing changelog
    assert violations(["packages/evals/dataset.jsonl", "packages/evals/DATA.md"]) == []
    assert violations(["apps/api/main.py"]) == []  # unrelated change

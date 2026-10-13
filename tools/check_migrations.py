"""Migration-safety check (CI job).

Rules enforced over the Alembic revisions in packages/schemas/alembic/versions:
1. No DROP TABLE / DROP COLUMN inside upgrade() unless the file carries a
   `# REVIEWED-DESTRUCTIVE:` marker with a human's justification.
2. Expand/contract discipline: a column may not be added AND set NOT NULL
   in the same migration — the NOT NULL enforcement must live in a later
   revision than the ADD COLUMN, so old code keeps working mid-deploy.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

VERSIONS = Path(__file__).resolve().parents[1] / "packages" / "schemas" / "alembic" / "versions"


def upgrade_body(source: str) -> str:
    match = re.search(r"def upgrade\(\).*?(?=\ndef downgrade|\Z)", source, re.DOTALL)
    return match.group(0) if match else ""


def check_file(path: Path) -> list[str]:
    source = path.read_text()
    body = upgrade_body(source)
    problems: list[str] = []
    if re.search(r"DROP\s+(TABLE|COLUMN)", body, re.IGNORECASE) and (
        "REVIEWED-DESTRUCTIVE:" not in source
    ):
        problems.append(
            f"{path.name}: destructive DROP in upgrade() without a "
            "# REVIEWED-DESTRUCTIVE: justification marker"
        )
    added = set(re.findall(r"ADD\s+COLUMN\s+(\w+)", body, re.IGNORECASE))
    enforced = set(re.findall(r"ALTER\s+COLUMN\s+(\w+)\s+SET\s+NOT\s+NULL", body, re.IGNORECASE))
    both = added & enforced
    if both:
        problems.append(
            f"{path.name}: columns added and set NOT NULL in the same migration "
            f"({sorted(both)}); split into expand + contract revisions"
        )
    return problems


def main() -> int:
    problems: list[str] = []
    for path in sorted(VERSIONS.glob("*.py")):
        problems.extend(check_file(path))
    if problems:
        print("MIGRATION SAFETY FAILURES:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"migration safety: OK ({len(list(VERSIONS.glob('*.py')))} revisions checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

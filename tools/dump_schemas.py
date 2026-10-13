"""Dump the JSON Schemas of all contract models to a committed file, or
check the committed file for drift (--check). Used by CI's schema-drift job."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from packages.schemas import models  # noqa: E402

OUT = ROOT / "packages" / "schemas" / "committed_schemas.json"

MODEL_NAMES = [
    "Alert",
    "IoC",
    "EnrichmentRecord",
    "EnrichmentResult",
    "InvestigationReport",
    "Verdict",
    "ApprovalRequest",
    "DeadLetterEntry",
]


def render() -> str:
    schemas = {name: getattr(models, name).model_json_schema() for name in MODEL_NAMES}
    return json.dumps(schemas, indent=2, sort_keys=True) + "\n"


def main() -> int:
    if "--check" in sys.argv:
        current = OUT.read_text() if OUT.exists() else ""
        if current != render():
            print("SCHEMA DRIFT: committed_schemas.json is stale; run tools/dump_schemas.py")
            return 1
        print("schemas up to date")
        return 0
    OUT.write_text(render())
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

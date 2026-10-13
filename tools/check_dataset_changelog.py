"""Dataset-regression check (CI job).

The golden dataset is versioned ground truth. A change to dataset.jsonl or
its generator (generate.py / pools.py) MUST ship with a DATA.md changelog
entry in the same change — otherwise labels can drift silently and every
downstream eval number becomes meaningless.

Usage: check_dataset_changelog.py <changed-file> [<changed-file> ...]
(CI passes `git diff --name-only <base>...HEAD`.)
"""

from __future__ import annotations

import sys

DATASET_FILES = {
    "packages/evals/dataset.jsonl",
    "packages/evals/generate.py",
    "packages/evals/pools.py",
}
CHANGELOG = "packages/evals/DATA.md"


def violations(changed: list[str]) -> list[str]:
    changed_set = set(changed)
    touched = changed_set & DATASET_FILES
    if touched and CHANGELOG not in changed_set:
        return [
            f"dataset files changed ({sorted(touched)}) without a {CHANGELOG} "
            "changelog entry in the same change"
        ]
    return []


def main() -> int:
    problems = violations(sys.argv[1:])
    if problems:
        print("DATASET REGRESSION CHECK FAILED:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("dataset changelog: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

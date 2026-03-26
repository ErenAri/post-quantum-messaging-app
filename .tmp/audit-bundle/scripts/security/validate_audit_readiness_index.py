#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
AUDIT_DOC = REPO_ROOT / "docs" / "AUDIT_READINESS.md"

PATH_PATTERN = re.compile(
    r"(?:\.github|crates|deploy|docs|mobile|observability|scripts|verification)/[A-Za-z0-9._/\-]+"
)


def iter_referenced_paths(text: str) -> list[str]:
    return sorted(set(PATH_PATTERN.findall(text)))


def main() -> int:
    text = AUDIT_DOC.read_text(encoding="utf-8")
    failures: list[str] = []
    for rel_path in iter_referenced_paths(text):
        if not (REPO_ROOT / rel_path).exists():
            failures.append(rel_path)

    if failures:
        for rel_path in failures:
            print(f"missing audit-readiness reference: {rel_path}", file=sys.stderr)
        return 1

    print(f"{AUDIT_DOC}: {len(iter_referenced_paths(text))} referenced paths verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

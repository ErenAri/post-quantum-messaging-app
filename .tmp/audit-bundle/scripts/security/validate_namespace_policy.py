#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


REQUIRED_PATTERNS = {
    "Namespace kind": re.compile(r"kind:\s*Namespace", re.MULTILINE),
    "enforce restricted": re.compile(
        r"pod-security\.kubernetes\.io/enforce:\s*restricted", re.MULTILINE
    ),
    "enforce version": re.compile(
        r"pod-security\.kubernetes\.io/enforce-version:\s*v1\.34", re.MULTILINE
    ),
    "audit restricted": re.compile(
        r"pod-security\.kubernetes\.io/audit:\s*restricted", re.MULTILINE
    ),
    "audit version": re.compile(
        r"pod-security\.kubernetes\.io/audit-version:\s*v1\.34", re.MULTILINE
    ),
    "warn restricted": re.compile(
        r"pod-security\.kubernetes\.io/warn:\s*restricted", re.MULTILINE
    ),
    "warn version": re.compile(
        r"pod-security\.kubernetes\.io/warn-version:\s*v1\.34", re.MULTILINE
    ),
}


def validate(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    return [label for label, pattern in REQUIRED_PATTERNS.items() if pattern.search(text) is None]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: validate_namespace_policy.py <namespace-manifest>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    if not path.is_file():
        print(f"{path}: file not found", file=sys.stderr)
        return 1
    missing = validate(path)
    if missing:
        print(f"{path}: missing " + ", ".join(missing), file=sys.stderr)
        return 1
    print(f"{path}: namespace policy checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

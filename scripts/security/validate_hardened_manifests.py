#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


REQUIRED_PATTERNS = {
    "automountServiceAccountToken false": re.compile(
        r"automountServiceAccountToken:\s*false", re.MULTILINE
    ),
    "enableServiceLinks false": re.compile(r"enableServiceLinks:\s*false", re.MULTILINE),
    "seccompProfile RuntimeDefault": re.compile(
        r"seccompProfile:\s*\n(?:\s+.*\n)*?\s+type:\s*RuntimeDefault",
        re.MULTILINE,
    ),
    "runAsNonRoot true": re.compile(r"runAsNonRoot:\s*true", re.MULTILINE),
    "allowPrivilegeEscalation false": re.compile(
        r"allowPrivilegeEscalation:\s*false", re.MULTILINE
    ),
    "readOnlyRootFilesystem true": re.compile(
        r"readOnlyRootFilesystem:\s*true", re.MULTILINE
    ),
    "drop ALL capabilities": re.compile(
        r"capabilities:\s*\n(?:\s+.*\n)*?\s+drop:\s*\n(?:\s+.*\n)*?\s+-\s*ALL",
        re.MULTILINE,
    ),
}


def validate_manifest(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    missing = [
        label for label, pattern in REQUIRED_PATTERNS.items() if pattern.search(text) is None
    ]
    return missing


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: validate_hardened_manifests.py <manifest> [<manifest> ...]", file=sys.stderr)
        return 2

    failures: list[str] = []
    for raw_path in argv[1:]:
        path = Path(raw_path)
        if not path.is_file():
            failures.append(f"{path}: file not found")
            continue
        missing = validate_manifest(path)
        if missing:
            failures.append(f"{path}: missing " + ", ".join(missing))

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    for raw_path in argv[1:]:
        print(f"{raw_path}: hardened manifest checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

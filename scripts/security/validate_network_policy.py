#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


REQUIRED_PATTERNS = {
    "NetworkPolicy kind": re.compile(r"kind:\s*NetworkPolicy", re.MULTILINE),
    "pod selector label": re.compile(
        r"podSelector:\s*\n(?:\s+.*\n)*?\s+app\.kubernetes\.io/name:\s*pqmsg-server",
        re.MULTILINE,
    ),
    "policyTypes Ingress": re.compile(r"policyTypes:\s*\n(?:\s+.*\n)*?\s+-\s*Ingress", re.MULTILINE),
    "policyTypes Egress": re.compile(r"policyTypes:\s*\n(?:\s+.*\n)*?\s+-\s*Egress", re.MULTILINE),
    "ingress port 8080": re.compile(r"port:\s*8080", re.MULTILINE),
    "egress port 53": re.compile(r"port:\s*53", re.MULTILINE),
    "egress port 5432": re.compile(r"port:\s*5432", re.MULTILINE),
    "egress port 6379": re.compile(r"port:\s*6379", re.MULTILINE),
    "egress port 443": re.compile(r"port:\s*443", re.MULTILINE),
    "egress port 4317": re.compile(r"port:\s*4317", re.MULTILINE),
}


def validate(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    return [label for label, pattern in REQUIRED_PATTERNS.items() if pattern.search(text) is None]


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: validate_network_policy.py <manifest> [<manifest> ...]", file=sys.stderr)
        return 2

    failures: list[str] = []
    for raw_path in argv[1:]:
        path = Path(raw_path)
        if not path.is_file():
            failures.append(f"{path}: file not found")
            continue
        missing = validate(path)
        if missing:
            failures.append(f"{path}: missing " + ", ".join(missing))

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    for raw_path in argv[1:]:
        print(f"{raw_path}: network policy checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

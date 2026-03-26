#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


PREVIEW_ENV_KEYS = (
    "PQMSG_CONTACT_DISCOVERY_SERVICE_ORIGIN",
    "PQMSG_CONTACT_DISCOVERY_MANIFEST_ED25519_PUB",
    "PQMSG_CONTACT_DISCOVERY_ATTESTATION_VERIFIER",
    "PQMSG_CONTACT_DISCOVERY_ENCLAVE_MEASUREMENT_HEX",
    "PQMSG_CONTACT_DISCOVERY_ATTESTATION_DOCUMENT_SHA256",
    "PQMSG_CONTACT_DISCOVERY_ATTESTATION_MAX_AGE_SECONDS",
)


def validate_manifest(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    failures: list[str] = []
    for key in PREVIEW_ENV_KEYS:
        if re.search(rf"(?m)^\s*{re.escape(key)}\s*:", text):
            failures.append(key)
    return failures


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(
            "usage: validate_no_preview_contact_discovery.py <manifest> [<manifest> ...]",
            file=sys.stderr,
        )
        return 2

    failures: list[str] = []
    for raw_path in argv[1:]:
        path = Path(raw_path)
        if not path.is_file():
            failures.append(f"{path}: file not found")
            continue
        blocked = validate_manifest(path)
        if blocked:
            failures.append(
                f"{path}: preview-only contact discovery envs present: {', '.join(blocked)}"
            )

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    for raw_path in argv[1:]:
        print(f"{raw_path}: no preview contact discovery envs found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

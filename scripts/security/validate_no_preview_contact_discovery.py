#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


DEPRECATED_PREVIEW_MARKERS = [
    "blind_token_directory_preview",
    "blind_evaluation_preview",
    "simulated_enclave_preview",
    "unattested_development",
    "service_boundary_only",
    "sgx_preview",
    "sgx-dcap-preview",
    "simulated-host-preview",
    "simulated-preview",
    "ristretto255-sha512-preview",
    "dleq_per_element_preview",
    "nonce_b64_required_preview",
]


def validate(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    failures: list[str] = []
    for marker in DEPRECATED_PREVIEW_MARKERS:
        if marker in text:
            failures.append(f"contains deprecated preview marker {marker!r}")
    return failures


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(
            "usage: validate_no_preview_contact_discovery.py <manifest> [<manifest> ...]",
            file=sys.stderr,
        )
        return 2

    errors: list[str] = []
    for raw_path in argv[1:]:
        path = Path(raw_path)
        if not path.is_file():
            errors.append(f"{path}: file not found")
            continue
        failures = validate(path)
        if failures:
            errors.append(f"{path}: " + "; ".join(failures))

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    for raw_path in argv[1:]:
        print(f"{raw_path}: no deprecated preview contact discovery markers found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

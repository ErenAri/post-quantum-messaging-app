#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


IMAGE_PATTERN = re.compile(r'^\s*image:\s*"?(?P<image>[^"\s]+)"?\s*$', re.MULTILINE)


def validate(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    images = IMAGE_PATTERN.findall(text)
    failures: list[str] = []
    if not images:
        failures.append("missing image reference")
        return failures
    for image in images:
        if image.endswith(":latest"):
            failures.append(f"mutable latest tag: {image}")
        if "@sha256:" not in image:
            failures.append(f"image is not digest pinned: {image}")
            continue
        repo, digest = image.split("@sha256:", 1)
        if not repo:
            failures.append(f"image repository missing in {image}")
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            failures.append(f"image digest is not 64 lowercase hex chars: {image}")
    return failures


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: validate_image_pinning.py <manifest> [<manifest> ...]", file=sys.stderr)
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
        print(f"{raw_path}: image pinning checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

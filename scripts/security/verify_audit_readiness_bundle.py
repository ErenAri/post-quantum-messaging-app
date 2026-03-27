#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_bundle(bundle_dir: Path) -> dict:
    manifest_path = bundle_dir / "audit-bundle-manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"missing bundle manifest: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise ValueError("invalid audit bundle manifest: missing entries list")

    failures: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            failures.append("manifest entry is not an object")
            continue
        rel_path = entry.get("path")
        expected_sha256 = entry.get("sha256")
        expected_size = entry.get("size_bytes")
        if not isinstance(rel_path, str) or not isinstance(expected_sha256, str):
            failures.append(f"invalid manifest entry: {entry!r}")
            continue
        target = bundle_dir / rel_path
        if not target.is_file():
            failures.append(f"missing file: {rel_path}")
            continue
        actual_sha256 = sha256_file(target)
        if actual_sha256 != expected_sha256:
            failures.append(
                f"sha256 mismatch for {rel_path}: expected {expected_sha256}, got {actual_sha256}"
            )
        if isinstance(expected_size, int) and target.stat().st_size != expected_size:
            failures.append(
                f"size mismatch for {rel_path}: expected {expected_size}, got {target.stat().st_size}"
            )

    if failures:
        raise ValueError("; ".join(failures))
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify an audit-readiness bundle against its manifest."
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        help="Directory containing audit-bundle-manifest.json and referenced files",
    )
    args = parser.parse_args()

    bundle_dir = Path(args.bundle_dir)
    try:
        manifest = verify_bundle(bundle_dir)
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "bundle_dir": str(bundle_dir),
                "files_verified": len(manifest.get("entries", [])),
                "git_commit": manifest.get("git_commit"),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

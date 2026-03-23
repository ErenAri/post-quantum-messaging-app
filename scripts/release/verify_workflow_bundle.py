#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a promotion or rollback workflow evidence bundle")
    parser.add_argument("--bundle-kind", required=True, choices=["promotion", "rollback"])
    parser.add_argument("--dist-dir", required=True)
    parser.add_argument("--repo", default="")
    args = parser.parse_args()

    dist_dir = Path(args.dist_dir)
    if not dist_dir.is_dir():
        raise SystemExit(f"workflow bundle directory not found: {dist_dir}")

    manifest_path = dist_dir / f"{args.bundle_kind}-bundle-manifest.json"
    if not manifest_path.is_file():
        raise SystemExit(f"missing workflow bundle manifest: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("bundle_kind") != args.bundle_kind:
        raise SystemExit(
            f"bundle manifest kind mismatch: expected {args.bundle_kind}, got {manifest.get('bundle_kind')}"
        )

    files = manifest.get("files")
    if not isinstance(files, list):
        raise SystemExit("bundle manifest does not contain a files array")

    for item in files:
        rel = item.get("path")
        if not isinstance(rel, str) or not rel or "/" in rel or "\\" in rel:
            raise SystemExit(f"invalid bundle manifest entry path: {rel!r}")
        target = dist_dir / rel
        if not target.is_file():
            raise SystemExit(f"bundle manifest entry points to missing file: {target}")
        expected_size = item.get("size_bytes")
        expected_hash = item.get("sha256")
        if not isinstance(expected_size, int) or expected_size < 0:
            raise SystemExit(f"bundle manifest entry has invalid size for {rel}")
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            raise SystemExit(f"bundle manifest entry has invalid sha256 for {rel}")
        if target.stat().st_size != expected_size:
            raise SystemExit(f"bundle manifest size mismatch for {rel}")
        actual_hash = sha256(target)
        if actual_hash.lower() != expected_hash.lower():
            raise SystemExit(f"bundle manifest sha256 mismatch for {rel}")

    if args.repo.strip():
        gh = shutil.which("gh")
        if gh:
            subprocess.run(
                [gh, "attestation", "verify", str(manifest_path), "-R", args.repo.strip()],
                check=True,
                text=True,
            )
        else:
            print("gh CLI not found; skipping workflow bundle attestation verification")

    print(f"{args.bundle_kind} workflow bundle verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

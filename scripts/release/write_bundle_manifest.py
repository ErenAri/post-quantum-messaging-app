#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Write a SHA-256 manifest for a promotion or rollback evidence bundle")
    parser.add_argument("--bundle-kind", required=True, choices=["promotion", "rollback"])
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--deployment-mode", required=True)
    parser.add_argument("--dist-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    dist_dir = Path(args.dist_dir)
    output = Path(args.output)
    output_name = output.name

    files: list[dict[str, object]] = []
    for path in sorted(dist_dir.glob("*")):
        if not path.is_file() or path.name == output_name:
            continue
        files.append(
            {
                "path": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            {
                "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "bundle_kind": args.bundle_kind,
                "release_tag": args.release_tag,
                "deployment_mode": args.deployment_mode,
                "dist_dir": str(dist_dir),
                "file_count": len(files),
                "files": files,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import build_audit_readiness_bundle
import verify_audit_readiness_bundle


REPO_ROOT = Path(__file__).resolve().parents[2]


def write_sha256(path: Path) -> str:
    digest = build_audit_readiness_bundle.sha256_file(path)
    path.with_suffix(path.suffix + ".sha256").write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return digest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a reviewer-friendly external audit handoff package from the audit bundle."
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        help="Directory containing the built audit-readiness bundle",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory to create or replace with the external handoff package",
    )
    args = parser.parse_args()

    bundle_dir = Path(args.bundle_dir)
    output_dir = Path(args.output_dir)

    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest = verify_audit_readiness_bundle.verify_bundle(bundle_dir)

    archive_base = output_dir / "audit-readiness-bundle"
    archive_path = Path(
        shutil.make_archive(str(archive_base), "zip", root_dir=bundle_dir, base_dir=".")
    )
    archive_sha256 = write_sha256(archive_path)

    support_matrix = json.loads(
        (REPO_ROOT / "docs" / "SUPPORT_MATRIX.json").read_text(encoding="utf-8")
    )
    handoff = {
        "handoff_type": "external_audit",
        "git_commit": manifest.get("git_commit"),
        "bundle_manifest": {
            "path": "audit-bundle-manifest.json",
            "sha256": build_audit_readiness_bundle.sha256_file(
                bundle_dir / "audit-bundle-manifest.json"
            ),
        },
        "bundle_archive": {
            "path": archive_path.name,
            "sha256": archive_sha256,
            "size_bytes": archive_path.stat().st_size,
        },
        "support_matrix": support_matrix.get("current_beta_scope"),
        "verification": {
            "bundle_dir_command": f"python scripts/security/verify_audit_readiness_bundle.py --bundle-dir {bundle_dir}",
            "archive_sha256_file": archive_path.with_suffix(archive_path.suffix + ".sha256").name,
        },
    }
    (output_dir / "audit-handoff.json").write_text(
        json.dumps(handoff, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    shutil.copy2(bundle_dir / "audit-bundle-manifest.json", output_dir / "audit-bundle-manifest.json")

    print(
        json.dumps(
            {
                "output_dir": str(output_dir),
                "archive": archive_path.name,
                "git_commit": manifest.get("git_commit"),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


INCLUDED_PATHS = [
    "README.md",
    "docs/AUDIT_READINESS.md",
    "docs/AUDIT_FINDINGS.json",
    "docs/API.md",
    "docs/DEPLOYMENT.md",
    "docs/FULL_PAGE_ENCRYPTION_PLAN.md",
    "docs/FORMAL_AUDIT.md",
    "docs/OBSERVABILITY.md",
    "docs/OPERATIONS.md",
    "docs/PRIVATE_CONTACT_DISCOVERY.md",
    "docs/PRIVATE_GROUPS.md",
    "docs/RELEASE_GOVERNANCE.md",
    "docs/SPEC.md",
    "docs/SUPPORT_MATRIX.json",
    "docs/THREAT_MODEL.md",
    "docs/WEB.md",
    ".github/workflows/ci.yml",
    ".github/workflows/release.yml",
    ".github/workflows/promote.yml",
    ".github/workflows/rollback.yml",
    ".github/ISSUE_TEMPLATE/security-audit-finding.yml",
    "scripts/security/pentest_smoke.sh",
    "scripts/security/pentest_smoke.ps1",
    "scripts/security/validate_audit_findings.py",
    "scripts/security/validate_hardened_manifests.py",
    "scripts/security/validate_image_pinning.py",
    "scripts/security/validate_namespace_policy.py",
    "scripts/security/validate_network_policy.py",
    "scripts/security/validate_audit_readiness_index.py",
    "scripts/security/validate_no_preview_contact_discovery.py",
    "scripts/security/prepare_external_audit_handoff.py",
    "scripts/security/render_audit_findings_report.py",
    "scripts/security/render_release_security_posture.py",
    "scripts/security/validate_audit_findings.py",
    "scripts/security/validate_release_audit_gate.py",
    "scripts/security/upsert_audit_finding.py",
    "scripts/security/validate_release_governance_workflows.py",
    "scripts/security/validate_support_matrix.py",
    "scripts/security/verify_audit_readiness_bundle.py",
]


@dataclass(frozen=True)
class BundleEntry:
    path: str
    sha256: str
    size_bytes: int


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_value(*args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        value = result.stdout.strip()
        return value or None
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


def build_bundle(output_dir: Path) -> dict:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    entries: list[BundleEntry] = []
    for rel_path in INCLUDED_PATHS:
        source = REPO_ROOT / rel_path
        if not source.is_file():
            raise FileNotFoundError(f"missing required audit artifact: {rel_path}")
        destination = output_dir / rel_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        entries.append(
            BundleEntry(
                path=rel_path,
                sha256=sha256_file(source),
                size_bytes=source.stat().st_size,
            )
        )

    manifest = {
        "bundle_type": "audit_readiness",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": git_value("rev-parse", "HEAD"),
        "git_branch": git_value("rev-parse", "--abbrev-ref", "HEAD"),
        "entries": [entry.__dict__ for entry in entries],
    }
    (output_dir / "audit-bundle-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a hashed audit-readiness bundle from repository artifacts."
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory to create or replace with the generated bundle",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    manifest = build_bundle(output_dir)
    print(
        json.dumps(
            {
                "output_dir": str(output_dir),
                "files": len(manifest["entries"]),
                "git_commit": manifest["git_commit"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

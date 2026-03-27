#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import validate_audit_findings
import validate_release_audit_gate


REPO_ROOT = Path(__file__).resolve().parents[2]
SUPPORT_MATRIX_PATH = REPO_ROOT / "docs" / "SUPPORT_MATRIX.json"
AUDIT_FINDINGS_PATH = REPO_ROOT / "docs" / "AUDIT_FINDINGS.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_posture() -> dict:
    support_matrix = json.loads(SUPPORT_MATRIX_PATH.read_text(encoding="utf-8"))
    findings_payload = validate_audit_findings.validate_registry(AUDIT_FINDINGS_PATH)
    audit_gate = validate_release_audit_gate.evaluate_gate(
        AUDIT_FINDINGS_PATH, set(validate_release_audit_gate.DEFAULT_BLOCK_SEVERITIES)
    )

    return {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "support_matrix": {
            "path": "docs/SUPPORT_MATRIX.json",
            "sha256": sha256_file(SUPPORT_MATRIX_PATH),
            "current_beta_scope": support_matrix.get("current_beta_scope"),
        },
        "audit_findings": {
            "path": "docs/AUDIT_FINDINGS.json",
            "sha256": sha256_file(AUDIT_FINDINGS_PATH),
            "total_findings": len(findings_payload.get("findings", [])),
        },
        "release_audit_gate": audit_gate,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render machine-readable release security posture evidence."
    )
    parser.add_argument("--output", required=True, help="Path to the output JSON file")
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(build_posture(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output_path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

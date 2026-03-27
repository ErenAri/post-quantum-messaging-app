#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import validate_audit_engagements
import validate_release_audit_gate


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate that a real external audit engagement has completed and closeout is release-ready."
    )
    parser.add_argument("--findings", default="docs/AUDIT_FINDINGS.json")
    parser.add_argument("--engagements", default="docs/AUDIT_ENGAGEMENTS.json")
    args = parser.parse_args()

    try:
        findings_report = validate_release_audit_gate.evaluate_gate(
            Path(args.findings), set(validate_release_audit_gate.DEFAULT_BLOCK_SEVERITIES)
        )
        engagements_payload = validate_audit_engagements.validate_registry(Path(args.engagements))
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    completed_external = [
        entry
        for entry in engagements_payload.get("engagements", [])
        if entry.get("type") == "external_audit" and entry.get("status") == "completed"
    ]
    report = {
        "findings_gate": findings_report,
        "completed_external_audits": [
            {
                "engagement_id": entry["engagement_id"],
                "auditor_name": entry["auditor_name"],
                "report_reference": entry["report_reference"],
                "completed_on_utc": entry["completed_on_utc"],
            }
            for entry in completed_external
        ],
    }
    print(json.dumps(report, indent=2, sort_keys=True))

    if findings_report["blocking_findings"]:
        return 1
    if not completed_external:
        print("no completed external_audit engagement recorded", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

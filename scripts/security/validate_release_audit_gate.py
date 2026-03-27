#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import validate_audit_findings


DEFAULT_BLOCK_SEVERITIES = ("critical", "high")
UNRESOLVED_STATUSES = {"open", "in_progress", "remediated_pending_verification"}


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def evaluate_gate(path: Path, block_severities: set[str]) -> dict:
    payload = validate_audit_findings.validate_registry(path)
    now = datetime.now(timezone.utc)
    blocking_findings: list[dict] = []
    accepted_findings: list[dict] = []

    for finding in payload["findings"]:
        severity = finding["severity"]
        status = finding["status"]
        if severity not in block_severities:
            continue

        if status in UNRESOLVED_STATUSES:
            blocking_findings.append(
                {
                    "finding_id": finding["finding_id"],
                    "severity": severity,
                    "status": status,
                    "reason": "unresolved_blocking_finding",
                }
            )
            continue

        if status == "risk_accepted":
            expiry = parse_utc(finding["risk_acceptance_expires_on_utc"])
            accepted_findings.append(
                {
                    "finding_id": finding["finding_id"],
                    "severity": severity,
                    "status": status,
                    "owner": finding["owner"],
                    "expires_on_utc": expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
            )
            if expiry <= now:
                blocking_findings.append(
                    {
                        "finding_id": finding["finding_id"],
                        "severity": severity,
                        "status": status,
                        "reason": "expired_risk_acceptance",
                    }
                )

    return {
        "path": str(path),
        "block_severities": sorted(block_severities),
        "blocking_findings": blocking_findings,
        "accepted_findings": accepted_findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail closed when release-blocking audit findings remain open."
    )
    parser.add_argument(
        "--path",
        default="docs/AUDIT_FINDINGS.json",
        help="Path to the audit findings registry",
    )
    parser.add_argument(
        "--block-severity",
        action="append",
        dest="block_severities",
        help="Severity to block; may be repeated. Defaults to critical and high.",
    )
    args = parser.parse_args()

    block_severities = set(args.block_severities or DEFAULT_BLOCK_SEVERITIES)
    try:
        report = evaluate_gate(Path(args.path), block_severities)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report["blocking_findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

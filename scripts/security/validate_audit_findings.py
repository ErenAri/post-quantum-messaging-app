#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
ALLOWED_STATUSES = {
    "open",
    "in_progress",
    "remediated_pending_verification",
    "closed",
    "risk_accepted",
}
ALLOWED_SOURCES = {
    "external_audit",
    "pentest",
    "formal_verification",
    "internal_review",
}
REQUIRED_FIELDS = {
    "finding_id",
    "source",
    "title",
    "severity",
    "affected_component",
    "exploit_path",
    "mitigation_plan",
    "verification_test",
    "status",
    "opened_on_utc",
}


def parse_utc(value: str, field_name: str) -> None:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid {field_name}: {value}") from exc


def require_non_empty_str(entry: dict, field_name: str, finding_id: str) -> str:
    value = entry.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{finding_id}: missing {field_name}")
    return value.strip()


def validate_finding(entry: dict, seen_ids: set[str]) -> None:
    if not isinstance(entry, dict):
        raise ValueError("finding entry is not an object")

    missing = REQUIRED_FIELDS - set(entry.keys())
    if missing:
        raise ValueError(f"finding entry missing required fields: {sorted(missing)}")

    finding_id = require_non_empty_str(entry, "finding_id", "<unknown>")
    if finding_id in seen_ids:
        raise ValueError(f"duplicate finding_id: {finding_id}")
    seen_ids.add(finding_id)

    source = require_non_empty_str(entry, "source", finding_id)
    if source not in ALLOWED_SOURCES:
        raise ValueError(f"{finding_id}: unsupported source {source}")

    severity = require_non_empty_str(entry, "severity", finding_id)
    if severity not in ALLOWED_SEVERITIES:
        raise ValueError(f"{finding_id}: unsupported severity {severity}")

    status = require_non_empty_str(entry, "status", finding_id)
    if status not in ALLOWED_STATUSES:
        raise ValueError(f"{finding_id}: unsupported status {status}")

    for field_name in (
        "title",
        "affected_component",
        "exploit_path",
        "mitigation_plan",
        "verification_test",
    ):
        require_non_empty_str(entry, field_name, finding_id)

    parse_utc(require_non_empty_str(entry, "opened_on_utc", finding_id), "opened_on_utc")

    closed_on = entry.get("closed_on_utc")
    if status in {"closed", "risk_accepted"}:
        if not isinstance(closed_on, str) or not closed_on.strip():
            raise ValueError(f"{finding_id}: closed findings require closed_on_utc")
        parse_utc(closed_on, "closed_on_utc")
    elif closed_on is not None:
        raise ValueError(f"{finding_id}: closed_on_utc is only valid for closed findings")

    if status == "risk_accepted":
        require_non_empty_str(entry, "risk_acceptance", finding_id)
        require_non_empty_str(entry, "owner", finding_id)
        parse_utc(
            require_non_empty_str(entry, "risk_acceptance_expires_on_utc", finding_id),
            "risk_acceptance_expires_on_utc",
        )

    references = entry.get("references")
    if references is not None:
        if not isinstance(references, list) or not all(
            isinstance(item, str) and item.strip() for item in references
        ):
            raise ValueError(f"{finding_id}: references must be a list of non-empty strings")


def validate_registry(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("registry must be a JSON object")
    if payload.get("version") != 1:
        raise ValueError("registry version must be 1")
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise ValueError("registry must contain a findings list")

    seen_ids: set[str] = set()
    for finding in findings:
        validate_finding(finding, seen_ids)

    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate the machine-readable audit findings registry."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="docs/AUDIT_FINDINGS.json",
        help="Path to the audit findings registry",
    )
    args = parser.parse_args()

    path = Path(args.path)
    try:
        payload = validate_registry(path)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    findings = payload["findings"]
    severity_counts = Counter(
        entry["severity"] for entry in findings if isinstance(entry, dict) and "severity" in entry
    )
    status_counts = Counter(
        entry["status"] for entry in findings if isinstance(entry, dict) and "status" in entry
    )
    print(
        json.dumps(
            {
                "path": str(path),
                "findings": len(findings),
                "severity_counts": dict(sorted(severity_counts.items())),
                "status_counts": dict(sorted(status_counts.items())),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

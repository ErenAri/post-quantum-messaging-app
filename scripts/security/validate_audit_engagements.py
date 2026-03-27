#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


ALLOWED_TYPES = {"external_audit", "pentest", "formal_review", "internal_review"}
ALLOWED_STATUSES = {"planned", "in_progress", "completed", "superseded"}
REQUIRED_FIELDS = {
    "engagement_id",
    "type",
    "auditor_name",
    "scope",
    "status",
    "opened_on_utc",
}


def parse_utc(value: str, field_name: str) -> None:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid {field_name}: {value}") from exc


def require_non_empty_str(entry: dict, field_name: str, engagement_id: str) -> str:
    value = entry.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{engagement_id}: missing {field_name}")
    return value.strip()


def validate_engagement(entry: dict, seen_ids: set[str]) -> None:
    if not isinstance(entry, dict):
        raise ValueError("engagement entry is not an object")

    missing = REQUIRED_FIELDS - set(entry.keys())
    if missing:
        raise ValueError(f"engagement entry missing required fields: {sorted(missing)}")

    engagement_id = require_non_empty_str(entry, "engagement_id", "<unknown>")
    if engagement_id in seen_ids:
        raise ValueError(f"duplicate engagement_id: {engagement_id}")
    seen_ids.add(engagement_id)

    engagement_type = require_non_empty_str(entry, "type", engagement_id)
    if engagement_type not in ALLOWED_TYPES:
        raise ValueError(f"{engagement_id}: unsupported type {engagement_type}")

    status = require_non_empty_str(entry, "status", engagement_id)
    if status not in ALLOWED_STATUSES:
        raise ValueError(f"{engagement_id}: unsupported status {status}")

    require_non_empty_str(entry, "auditor_name", engagement_id)
    require_non_empty_str(entry, "scope", engagement_id)
    parse_utc(require_non_empty_str(entry, "opened_on_utc", engagement_id), "opened_on_utc")

    completed_on = entry.get("completed_on_utc")
    if status == "completed":
        if not isinstance(completed_on, str) or not completed_on.strip():
            raise ValueError(f"{engagement_id}: completed engagements require completed_on_utc")
        parse_utc(completed_on, "completed_on_utc")
        require_non_empty_str(entry, "report_reference", engagement_id)
    elif completed_on is not None:
        raise ValueError(f"{engagement_id}: completed_on_utc is only valid for completed engagements")


def validate_registry(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("registry must be a JSON object")
    if payload.get("version") != 1:
        raise ValueError("registry version must be 1")
    engagements = payload.get("engagements")
    if not isinstance(engagements, list):
        raise ValueError("registry must contain an engagements list")

    seen_ids: set[str] = set()
    for engagement in engagements:
        validate_engagement(engagement, seen_ids)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate the machine-readable audit engagements registry."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="docs/AUDIT_ENGAGEMENTS.json",
        help="Path to the audit engagements registry",
    )
    args = parser.parse_args()

    path = Path(args.path)
    try:
        payload = validate_registry(path)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    engagements = payload["engagements"]
    type_counts = Counter(
        entry["type"] for entry in engagements if isinstance(entry, dict) and "type" in entry
    )
    status_counts = Counter(
        entry["status"] for entry in engagements if isinstance(entry, dict) and "status" in entry
    )
    print(
        json.dumps(
            {
                "path": str(path),
                "engagements": len(engagements),
                "type_counts": dict(sorted(type_counts.items())),
                "status_counts": dict(sorted(status_counts.items())),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

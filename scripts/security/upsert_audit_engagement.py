#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import validate_audit_engagements


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_registry(path: Path) -> dict[str, Any]:
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"version": 1, "engagements": []}


def apply_value(entry: dict[str, Any], field_name: str, value: Any) -> None:
    if value is not None:
        entry[field_name] = value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create or update an entry in docs/AUDIT_ENGAGEMENTS.json."
    )
    parser.add_argument("--registry", default="docs/AUDIT_ENGAGEMENTS.json")
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--type")
    parser.add_argument("--auditor-name")
    parser.add_argument("--scope")
    parser.add_argument("--status")
    parser.add_argument("--opened-on-utc")
    parser.add_argument("--completed-on-utc")
    parser.add_argument("--report-reference")
    args = parser.parse_args()

    registry_path = Path(args.registry)
    payload = load_registry(registry_path)
    engagements = payload.setdefault("engagements", [])

    existing = None
    for entry in engagements:
        if isinstance(entry, dict) and entry.get("engagement_id") == args.engagement_id:
            existing = entry
            break

    created = existing is None
    if existing is None:
        existing = {
            "engagement_id": args.engagement_id,
            "opened_on_utc": args.opened_on_utc or utc_now(),
        }
        engagements.append(existing)

    apply_value(existing, "type", args.type)
    apply_value(existing, "auditor_name", args.auditor_name)
    apply_value(existing, "scope", args.scope)
    apply_value(existing, "status", args.status)
    apply_value(existing, "opened_on_utc", args.opened_on_utc)
    apply_value(existing, "completed_on_utc", args.completed_on_utc)
    apply_value(existing, "report_reference", args.report_reference)

    if existing.get("status") == "completed" and "completed_on_utc" not in existing:
        existing["completed_on_utc"] = utc_now()

    engagements.sort(key=lambda entry: entry.get("engagement_id", ""))
    payload["version"] = 1
    registry_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validate_audit_engagements.validate_registry(registry_path)
    print(
        json.dumps(
            {
                "registry": str(registry_path),
                "engagement_id": args.engagement_id,
                "created": created,
                "status": existing.get("status"),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

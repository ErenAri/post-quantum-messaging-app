#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import validate_audit_findings


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_registry(path: Path) -> dict[str, Any]:
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"version": 1, "findings": []}


def apply_value(entry: dict[str, Any], field_name: str, value: Any) -> None:
    if value is not None:
        entry[field_name] = value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create or update an entry in docs/AUDIT_FINDINGS.json."
    )
    parser.add_argument("--registry", default="docs/AUDIT_FINDINGS.json")
    parser.add_argument("--finding-id", required=True)
    parser.add_argument("--source")
    parser.add_argument("--title")
    parser.add_argument("--severity")
    parser.add_argument("--affected-component")
    parser.add_argument("--exploit-path")
    parser.add_argument("--mitigation-plan")
    parser.add_argument("--verification-test")
    parser.add_argument("--status")
    parser.add_argument("--opened-on-utc")
    parser.add_argument("--closed-on-utc")
    parser.add_argument("--owner")
    parser.add_argument("--risk-acceptance")
    parser.add_argument("--risk-acceptance-expires-on-utc")
    parser.add_argument("--reference", action="append", dest="references")
    parser.add_argument(
        "--clear-references",
        action="store_true",
        help="Replace references with an empty list",
    )
    args = parser.parse_args()

    registry_path = Path(args.registry)
    payload = load_registry(registry_path)
    findings = payload.setdefault("findings", [])

    existing = None
    for entry in findings:
        if isinstance(entry, dict) and entry.get("finding_id") == args.finding_id:
            existing = entry
            break

    created = existing is None
    if existing is None:
        existing = {"finding_id": args.finding_id, "opened_on_utc": args.opened_on_utc or utc_now()}
        findings.append(existing)

    apply_value(existing, "source", args.source)
    apply_value(existing, "title", args.title)
    apply_value(existing, "severity", args.severity)
    apply_value(existing, "affected_component", args.affected_component)
    apply_value(existing, "exploit_path", args.exploit_path)
    apply_value(existing, "mitigation_plan", args.mitigation_plan)
    apply_value(existing, "verification_test", args.verification_test)
    apply_value(existing, "status", args.status)
    apply_value(existing, "opened_on_utc", args.opened_on_utc)
    apply_value(existing, "closed_on_utc", args.closed_on_utc)
    apply_value(existing, "owner", args.owner)
    apply_value(existing, "risk_acceptance", args.risk_acceptance)
    apply_value(
        existing,
        "risk_acceptance_expires_on_utc",
        args.risk_acceptance_expires_on_utc,
    )

    if args.clear_references:
        existing["references"] = []
    elif args.references is not None:
        existing["references"] = args.references

    if existing.get("status") in {"closed", "risk_accepted"} and "closed_on_utc" not in existing:
        existing["closed_on_utc"] = utc_now()

    findings.sort(key=lambda entry: entry.get("finding_id", ""))
    payload["version"] = 1
    registry_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validate_audit_findings.validate_registry(registry_path)
    print(
        json.dumps(
            {
                "registry": str(registry_path),
                "finding_id": args.finding_id,
                "created": created,
                "status": existing.get("status"),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

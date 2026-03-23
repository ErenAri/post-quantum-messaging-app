#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def slugify(value: str | None) -> str:
    if not value:
        return "unknown"
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "unknown"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def choose_severity(record: dict[str, Any]) -> str:
    deployment_mode = (record.get("record_context", {}) or {}).get("deployment_mode", "")
    job_status = str(record.get("job_status", "")).lower()
    suspicious = int(record.get("suspicious_drift_count", 0))
    failed_checks = record.get("failed_checks", []) or []

    critical_sources = {"runtime_contract", "live_policy", "live_routing", "drift_report"}
    if suspicious > 0:
        return "critical"
    if any(item.get("source") in critical_sources for item in failed_checks):
        return "critical" if deployment_mode == "production" else "high"
    if job_status != "success":
        return "high" if deployment_mode == "production" else "medium"
    return "medium"


def top_failed_checks(record: dict[str, Any], limit: int = 4) -> list[str]:
    rows: list[str] = []
    for item in (record.get("failed_checks") or [])[:limit]:
        source = item.get("source", "unknown")
        name = item.get("name", "unknown_check")
        rows.append(f"{source}:{name}")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Write Alertmanager-compatible incident payload")
    parser.add_argument("--failure-handoff", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--output-md", required=True)
    args = parser.parse_args()

    handoff = load_json(Path(args.failure_handoff))
    context = handoff.get("record_context", {}) or {}
    operation = handoff.get("operation", "unknown")
    severity = choose_severity(handoff)
    release_tag = context.get("release_tag") or "unknown"
    environment = context.get("environment_name") or "unknown"
    deployment_mode = context.get("deployment_mode") or "unknown"
    release_name = context.get("release_name") or "unknown"
    namespace = context.get("namespace") or "unknown"
    target_image = context.get("target_image") or "unknown"
    failed_count = int(handoff.get("failed_check_count", 0))
    suspicious_count = int(handoff.get("suspicious_drift_count", 0))
    failed_summary = top_failed_checks(handoff)

    summary = (
        f"pqmsg {operation} incident: {release_tag} "
        f"({environment}/{deployment_mode}) severity={severity}"
    )
    description_parts = [
        f"Operation: {operation}",
        f"Release: {release_tag}",
        f"Environment: {environment}",
        f"Deployment mode: {deployment_mode}",
        f"Release name: {release_name}",
        f"Namespace: {namespace}",
        f"Target image: {target_image}",
        f"Job status: {handoff.get('job_status', 'unknown')}",
        f"Failed checks: {failed_count}",
        f"Suspicious drift: {suspicious_count}",
    ]
    if failed_summary:
        description_parts.append("Top failed checks: " + ", ".join(failed_summary))

    alert = {
        "labels": {
            "alertname": "PQMSGReleaseWorkflowIncident",
            "service": "pqmsg-release-governance",
            "severity": severity,
            "operation": slugify(operation),
            "environment": slugify(environment),
            "deployment_mode": slugify(deployment_mode),
            "release_name": slugify(release_name),
            "namespace": slugify(namespace),
            "release_tag": slugify(release_tag),
        },
        "annotations": {
            "summary": summary,
            "description": " | ".join(description_parts),
        },
        "startsAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    Path(args.output_json).write_text(json.dumps([alert], indent=2) + "\n", encoding="utf-8")

    next_actions = handoff.get("next_actions") or []
    lines = [
        f"# {summary}",
        "",
        f"- Operation: `{operation}`",
        f"- Release tag: `{release_tag}`",
        f"- Environment: `{environment}`",
        f"- Deployment mode: `{deployment_mode}`",
        f"- Release name: `{release_name}`",
        f"- Namespace: `{namespace}`",
        f"- Target image: `{target_image}`",
        f"- Job status: `{handoff.get('job_status', 'unknown')}`",
        f"- Failed check count: `{failed_count}`",
        f"- Suspicious drift count: `{suspicious_count}`",
    ]
    if failed_summary:
        lines.append(f"- Top failed checks: `{', '.join(failed_summary)}`")
    if next_actions:
        lines.append("")
        lines.append("## Next Actions")
        for item in next_actions:
            lines.append(f"- {item}")

    Path(args.output_md).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

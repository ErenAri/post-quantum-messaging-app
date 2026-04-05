#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_MANUAL_STEP_IDS = (
    "provision_two_fresh_android_users",
    "direct_messages_both_directions",
    "private_group_create_and_message",
    "attachments_dm_and_private_group",
    "restart_and_inbox_sync_continuity",
    "trust_change_fail_closed_behavior",
    "stale_private_group_state_fail_closed_behavior",
)
VALID_STATUSES = {"pass", "fail", "pending"}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_utc(raw_value: str) -> str:
    parsed = datetime.fromisoformat(raw_value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_report(path: Path, expected_phase: str) -> dict[str, Any]:
    report = load_json(path)
    if report.get("phase") != expected_phase:
        raise ValueError(f"{path}: expected phase '{expected_phase}'")

    failed_checks = [
        check["name"]
        for check in report.get("checks", [])
        if check.get("status") != "ok"
    ]
    if failed_checks:
        raise ValueError(f"{path}: non-ok checks present: {', '.join(failed_checks)}")

    if expected_phase == "launch":
        live_runtime = report.get("live_runtime")
        if not isinstance(live_runtime, dict):
            raise ValueError(f"{path}: missing live_runtime section")
        runtime_failures = [
            check["name"]
            for check in live_runtime.get("checks", [])
            if not bool(check.get("passed", False))
        ]
        if runtime_failures:
            raise ValueError(f"{path}: live runtime checks failed: {', '.join(runtime_failures)}")

    return report


def validate_manual_smoke(path: Path) -> dict[str, Any]:
    payload = load_json(path)
    raw_steps = payload.get("steps")
    if not isinstance(raw_steps, list):
        raise ValueError(f"{path}: steps must be a list")

    by_id: dict[str, dict[str, Any]] = {}
    for entry in raw_steps:
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: each step must be an object")
        step_id = entry.get("id")
        if not isinstance(step_id, str) or not step_id:
            raise ValueError(f"{path}: each step must include a non-empty id")
        if step_id in by_id:
            raise ValueError(f"{path}: duplicate step id '{step_id}'")

        status = entry.get("status")
        if status not in VALID_STATUSES:
            raise ValueError(f"{path}: step '{step_id}' has invalid status '{status}'")

        tester = entry.get("tester")
        if not isinstance(tester, str):
            raise ValueError(f"{path}: step '{step_id}' tester must be a string")

        completed_at = entry.get("completed_at_utc", "")
        normalized_completed_at = ""
        if completed_at:
            normalized_completed_at = parse_utc(completed_at)

        by_id[step_id] = {
            "id": step_id,
            "description": entry.get("description", ""),
            "status": status,
            "tester": tester,
            "completed_at_utc": normalized_completed_at,
            "notes": entry.get("notes", ""),
        }

    missing = [step_id for step_id in REQUIRED_MANUAL_STEP_IDS if step_id not in by_id]
    if missing:
        raise ValueError(f"{path}: missing required manual smoke steps: {', '.join(missing)}")

    failed = []
    pending = []
    for step_id in REQUIRED_MANUAL_STEP_IDS:
        step = by_id[step_id]
        if step["status"] == "fail":
            failed.append(step_id)
        elif step["status"] != "pass":
            pending.append(step_id)

    return {
        "steps": [by_id[step_id] for step_id in REQUIRED_MANUAL_STEP_IDS],
        "failed_step_ids": failed,
        "pending_step_ids": pending,
    }


def validate_promotion_record(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    record = load_json(path)
    if record.get("deployment_mode") != "pilot":
        raise ValueError(f"{path}: expected deployment_mode 'pilot'")
    if not bool(record.get("apply_requested")):
        raise ValueError(f"{path}: expected apply_requested=true")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description="Write a structured Android pilot launch handoff record.")
    parser.add_argument("--candidate-readiness", required=True)
    parser.add_argument("--launch-readiness", required=True)
    parser.add_argument("--manual-smoke", required=True)
    parser.add_argument("--promotion-record")
    parser.add_argument("--cohort-users", type=int, default=5)
    parser.add_argument("--operator-users", type=int, default=2)
    parser.add_argument("--pilot-days", type=int, default=7)
    parser.add_argument("--release-owner", required=True)
    parser.add_argument("--rollback-owner", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    candidate_report = validate_report(Path(args.candidate_readiness), "candidate")
    launch_report = validate_report(Path(args.launch_readiness), "launch")
    manual_smoke = validate_manual_smoke(Path(args.manual_smoke))
    promotion_record = validate_promotion_record(Path(args.promotion_record)) if args.promotion_record else None

    failed_requirements: list[str] = []
    if manual_smoke["failed_step_ids"]:
        failed_requirements.append(
            "manual_smoke_failed_steps:" + ",".join(manual_smoke["failed_step_ids"])
        )
    if manual_smoke["pending_step_ids"]:
        failed_requirements.append(
            "manual_smoke_pending_steps:" + ",".join(manual_smoke["pending_step_ids"])
        )

    ready_for_cohort_launch = not failed_requirements
    next_actions: list[str] = []
    if not ready_for_cohort_launch:
        next_actions.append("Do not onboard pilot users until every manual smoke step is marked pass.")
        if manual_smoke["failed_step_ids"]:
            next_actions.append("Triage failed Android smoke steps before retrying launch signoff.")
        if manual_smoke["pending_step_ids"]:
            next_actions.append("Complete all remaining Android smoke steps and update the handoff record.")

    support_matrix = candidate_report.get("support_matrix", {})
    live_runtime = launch_report.get("live_runtime", {})
    report = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ready_for_cohort_launch": ready_for_cohort_launch,
        "support_matrix_summary": support_matrix.get("summary"),
        "candidate_readiness_path": args.candidate_readiness,
        "launch_readiness_path": args.launch_readiness,
        "manual_smoke_path": args.manual_smoke,
        "promotion_record_path": args.promotion_record,
        "release_owner": args.release_owner,
        "rollback_owner": args.rollback_owner,
        "cohort_users": args.cohort_users,
        "operator_users": args.operator_users,
        "pilot_days": args.pilot_days,
        "failed_requirements": failed_requirements,
        "next_actions": next_actions,
        "candidate_readiness": {
            "generated_at_utc": candidate_report.get("generated_at_utc"),
            "check_count": len(candidate_report.get("checks", [])),
        },
        "launch_readiness": {
            "generated_at_utc": launch_report.get("generated_at_utc"),
            "check_count": len(launch_report.get("checks", [])),
            "live_runtime_server": live_runtime.get("server"),
            "live_runtime_check_count": len(live_runtime.get("checks", [])),
        },
        "promotion_context": promotion_record,
        "manual_smoke": manual_smoke["steps"],
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 1 if not ready_for_cohort_launch else 0


if __name__ == "__main__":
    raise SystemExit(main())

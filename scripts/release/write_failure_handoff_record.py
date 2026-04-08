#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_json_if_present(raw_path: str | None) -> Any | None:
    if not raw_path:
        return None
    path = Path(raw_path)
    if not path.is_file():
        return None
    if path.stat().st_size == 0:
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def collect_failed_checks(source: str, report: Any | None) -> list[dict[str, Any]]:
    if not isinstance(report, dict):
        return []
    failures: list[dict[str, Any]] = []
    for check in report.get("checks", []):
        if check.get("skipped") is True:
            continue
        if bool(check.get("passed", False)):
            continue
        details = check.get("details")
        if details is None:
            details = check.get("failures")
        if details is None:
            details = {}
        failures.append(
            {
                "source": source,
                "name": check.get("name", "unknown_check"),
                "details": details,
            }
        )
    return failures


def summarize_deployments(document: Any | None) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        return []
    rows: list[dict[str, Any]] = []
    for item in document.get("items", []):
        metadata = item.get("metadata", {})
        status = item.get("status", {})
        rows.append(
            {
                "name": metadata.get("name"),
                "resourceVersion": metadata.get("resourceVersion"),
                "generation": metadata.get("generation"),
                "observedGeneration": status.get("observedGeneration"),
                "replicas": status.get("replicas", 0),
                "readyReplicas": status.get("readyReplicas", 0),
                "availableReplicas": status.get("availableReplicas", 0),
            }
        )
    return rows


def summarize_non_ready_pods(document: Any | None) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        return []
    rows: list[dict[str, Any]] = []
    for item in document.get("items", []):
        metadata = item.get("metadata", {})
        status = item.get("status", {})
        pod_name = metadata.get("name")
        phase = status.get("phase")
        container_statuses = status.get("containerStatuses", [])
        if not container_statuses:
            rows.append({"pod": pod_name, "phase": phase, "container": None, "reason": "no_container_status"})
            continue
        for container in container_statuses:
            ready = bool(container.get("ready", False))
            restart_count = int(container.get("restartCount", 0))
            state = container.get("state", {})
            if ready and phase == "Running" and restart_count == 0:
                continue
            rows.append(
                {
                    "pod": pod_name,
                    "phase": phase,
                    "container": container.get("name"),
                    "ready": ready,
                    "restartCount": restart_count,
                    "state": state,
                }
            )
    return rows


def artifact_state(raw_path: str | None) -> dict[str, Any]:
    if not raw_path:
        return {"path": None, "present": False}
    path = Path(raw_path)
    return {
        "path": raw_path,
        "present": path.is_file(),
        "size_bytes": path.stat().st_size if path.is_file() else 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Write incident-ready promotion/rollback failure record")
    parser.add_argument("--operation", choices=["promote", "rollback"], required=True)
    parser.add_argument("--job-status", required=True)
    parser.add_argument("--record")
    parser.add_argument("--cluster-contract")
    parser.add_argument("--runtime-verification")
    parser.add_argument("--policy-verification")
    parser.add_argument("--routing-verification")
    parser.add_argument("--drift-report")
    parser.add_argument("--deployments")
    parser.add_argument("--pods")
    parser.add_argument("--port-forward-log")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    record = load_json_if_present(args.record)
    cluster_contract = load_json_if_present(args.cluster_contract)
    runtime_verification = load_json_if_present(args.runtime_verification)
    policy_verification = load_json_if_present(args.policy_verification)
    routing_verification = load_json_if_present(args.routing_verification)
    drift_report = load_json_if_present(args.drift_report)
    deployments = load_json_if_present(args.deployments)
    pods = load_json_if_present(args.pods)

    failures: list[dict[str, Any]] = []
    failures.extend(collect_failed_checks("cluster_contract", cluster_contract))
    failures.extend(collect_failed_checks("runtime_contract", runtime_verification))
    failures.extend(collect_failed_checks("live_policy", policy_verification))
    failures.extend(collect_failed_checks("live_routing", routing_verification))

    suspicious_changes = []
    suspicious_count = 0
    if isinstance(drift_report, dict):
        suspicious_changes = drift_report.get("suspicious_changes", [])
        suspicious_count = int(drift_report.get("suspicious_change_count", 0))
        if suspicious_count:
            failures.append(
                {
                    "source": "drift_report",
                    "name": "suspicious_cluster_drift",
                    "details": suspicious_changes,
                }
            )

    deployment_summary = summarize_deployments(deployments)
    non_ready_pods = summarize_non_ready_pods(pods)
    if non_ready_pods:
        failures.append(
            {
                "source": "rollout_state",
                "name": "non_ready_pods_present",
                "details": {"count": len(non_ready_pods)},
            }
        )

    incident_required = args.job_status.lower() != "success" or bool(failures)
    next_actions: list[str] = []
    if incident_required:
        next_actions.append("Freeze further promotion or rollback actions until the failing checks are reviewed.")
        if suspicious_count:
            next_actions.append("Review suspicious drift first, especially TLS secret and namespace policy changes.")
        if non_ready_pods:
            next_actions.append("Inspect non-ready pods and deployment rollout state before retrying.")
        if not runtime_verification:
            next_actions.append("Check rollout logs and the port-forward log because runtime contract verification did not complete.")
        elif any(item["source"] == "runtime_contract" for item in failures):
            next_actions.append("Triage runtime /health and /v1/capabilities mismatches before any further rollout.")
        if any(item["source"] == "live_policy" for item in failures):
            next_actions.append("Inspect live Deployment and NetworkPolicy state for hardened-policy regressions.")
        if any(item["source"] == "live_routing" for item in failures):
            next_actions.append("Inspect live Service/Ingress wiring and compare it to the rendered chart.")
        if any(item["source"] == "cluster_contract" for item in failures):
            next_actions.append("Fix namespace labels or missing prerequisite secrets/configmaps before re-running apply.")

    report = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "operation": args.operation,
        "job_status": args.job_status,
        "incident_required": incident_required,
        "record_context": {
            "release_tag": (record or {}).get("release_tag"),
            "namespace": (record or {}).get("namespace"),
            "release_name": (record or {}).get("release_name"),
            "environment_name": (record or {}).get("environment_name"),
            "deployment_mode": (record or {}).get("deployment_mode"),
            "target_image": (record or {}).get("target_image"),
        },
        "artifact_presence": {
            "record": artifact_state(args.record),
            "cluster_contract": artifact_state(args.cluster_contract),
            "runtime_verification": artifact_state(args.runtime_verification),
            "policy_verification": artifact_state(args.policy_verification),
            "routing_verification": artifact_state(args.routing_verification),
            "drift_report": artifact_state(args.drift_report),
            "deployments": artifact_state(args.deployments),
            "pods": artifact_state(args.pods),
            "port_forward_log": artifact_state(args.port_forward_log),
        },
        "failed_checks": failures,
        "failed_check_count": len(failures),
        "suspicious_drift_count": suspicious_count,
        "suspicious_drift": suspicious_changes,
        "deployment_rollout_state": deployment_summary,
        "non_ready_pods": non_ready_pods,
        "next_actions": next_actions,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

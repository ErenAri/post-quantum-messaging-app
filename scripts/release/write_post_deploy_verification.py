#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def check(name: str, value: bool, details: dict[str, Any]) -> dict[str, Any]:
    return {"name": name, "passed": bool(value), "details": details}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate post-deploy runtime contract")
    parser.add_argument("--health", required=True)
    parser.add_argument("--capabilities", required=True)
    parser.add_argument("--deployments", required=True)
    parser.add_argument("--pods", required=True)
    parser.add_argument("--promotion-record", required=True)
    parser.add_argument("--expected-deployment-mode", required=True)
    parser.add_argument("--expected-security-profile", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    health = load_json(Path(args.health))
    capabilities = load_json(Path(args.capabilities))
    deployments = load_json(Path(args.deployments))
    pods = load_json(Path(args.pods))
    promotion_record = load_json(Path(args.promotion_record))
    target_image = promotion_record["target_image"]

    deployment_images: list[dict[str, Any]] = []
    for item in deployments.get("items", []):
        deployment_name = item.get("metadata", {}).get("name", "")
        containers = item.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        status = item.get("status", {})
        for container in containers:
            deployment_images.append(
                {
                    "deployment": deployment_name,
                    "container": container.get("name", ""),
                    "image": container.get("image", ""),
                    "availableReplicas": status.get("availableReplicas", 0),
                    "readyReplicas": status.get("readyReplicas", 0),
                    "replicas": status.get("replicas", 0),
                }
            )

    pod_statuses: list[dict[str, Any]] = []
    for item in pods.get("items", []):
        pod_name = item.get("metadata", {}).get("name", "")
        phase = item.get("status", {}).get("phase", "")
        for container_status in item.get("status", {}).get("containerStatuses", []):
            pod_statuses.append(
                {
                    "pod": pod_name,
                    "container": container_status.get("name", ""),
                    "ready": bool(container_status.get("ready", False)),
                    "restartCount": int(container_status.get("restartCount", 0)),
                    "phase": phase,
                }
            )

    checks = [
        check("health_status_ok", health.get("status") == "ok", {"status": health.get("status")}),
        check("health_db_ready", health.get("db_ready") is True, {"db_ready": health.get("db_ready")}),
        check("health_tls_enabled", health.get("tls_enabled") is True, {"tls_enabled": health.get("tls_enabled")}),
        check(
            "health_audit_logger_enabled",
            health.get("audit_logger_enabled") is True,
            {"audit_logger_enabled": health.get("audit_logger_enabled")},
        ),
        check(
            "health_production_baseline_met",
            health.get("production_baseline_met") is True,
            {"production_baseline_met": health.get("production_baseline_met")},
        ),
        check(
            "health_deployment_mode_match",
            health.get("deployment_mode") == args.expected_deployment_mode,
            {"expected": args.expected_deployment_mode, "actual": health.get("deployment_mode")},
        ),
        check(
            "health_security_profile_match",
            health.get("security_profile") == args.expected_security_profile,
            {"expected": args.expected_security_profile, "actual": health.get("security_profile")},
        ),
        check(
            "capabilities_tls_required",
            capabilities.get("tls_required") is True,
            {"tls_required": capabilities.get("tls_required")},
        ),
        check(
            "capabilities_tls_enabled",
            capabilities.get("tls_enabled") is True,
            {"tls_enabled": capabilities.get("tls_enabled")},
        ),
        check(
            "capabilities_production_baseline_met",
            capabilities.get("production_baseline_met") is True,
            {"production_baseline_met": capabilities.get("production_baseline_met")},
        ),
        check(
            "capabilities_deployment_mode_match",
            capabilities.get("deployment_mode") == args.expected_deployment_mode,
            {"expected": args.expected_deployment_mode, "actual": capabilities.get("deployment_mode")},
        ),
        check(
            "capabilities_security_profile_match",
            capabilities.get("security_profile") == args.expected_security_profile,
            {"expected": args.expected_security_profile, "actual": capabilities.get("security_profile")},
        ),
        check(
            "capabilities_sealed_sender_required",
            capabilities.get("sealed_sender_required") is True,
            {"sealed_sender_required": capabilities.get("sealed_sender_required")},
        ),
        check(
            "capabilities_authenticated_dm_disabled",
            capabilities.get("authenticated_direct_messaging_supported") is False,
            {
                "authenticated_direct_messaging_supported": capabilities.get(
                    "authenticated_direct_messaging_supported"
                )
            },
        ),
        check(
            "capabilities_sender_certificates_enabled",
            capabilities.get("sender_certificate_supported") is True,
            {"sender_certificate_supported": capabilities.get("sender_certificate_supported")},
        ),
        check(
            "capabilities_key_transparency_enabled",
            capabilities.get("key_transparency_supported") is True,
            {"key_transparency_supported": capabilities.get("key_transparency_supported")},
        ),
        check(
            "deployment_present",
            len(deployment_images) > 0,
            {"deployments": len(deployments.get("items", []))},
        ),
        check(
            "deployment_images_match_target",
            bool(deployment_images) and all(entry["image"] == target_image for entry in deployment_images),
            {"target_image": target_image, "images": deployment_images},
        ),
        check("pods_present", len(pod_statuses) > 0, {"pods": len(pods.get("items", []))}),
        check(
            "all_pod_containers_ready",
            bool(pod_statuses) and all(entry["ready"] and entry["phase"] == "Running" for entry in pod_statuses),
            {"pods": pod_statuses},
        ),
    ]

    failed = [item for item in checks if not item["passed"]]
    report = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expected_deployment_mode": args.expected_deployment_mode,
        "expected_security_profile": args.expected_security_profile,
        "target_image": target_image,
        "passed": not failed,
        "checks": checks,
    }
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if failed:
        for item in failed:
            print(f"post-deploy verification failed: {item['name']} -> {item['details']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

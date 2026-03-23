#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_NAMESPACE_LABELS = {
    "pod-security.kubernetes.io/enforce": "restricted",
    "pod-security.kubernetes.io/enforce-version": "v1.34",
    "pod-security.kubernetes.io/audit": "restricted",
    "pod-security.kubernetes.io/audit-version": "v1.34",
    "pod-security.kubernetes.io/warn": "restricted",
    "pod-security.kubernetes.io/warn-version": "v1.34",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def index_items(document: Any) -> dict[str, Any]:
    return {
        item.get("metadata", {}).get("name", ""): item
        for item in document.get("items", [])
        if item.get("metadata", {}).get("name")
    }


def deployment_summary(item: Any | None) -> dict[str, Any] | None:
    if not item:
        return None
    metadata = item.get("metadata", {})
    status = item.get("status", {})
    containers = item.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
    return {
        "resourceVersion": metadata.get("resourceVersion"),
        "generation": metadata.get("generation"),
        "observedGeneration": status.get("observedGeneration"),
        "availableReplicas": status.get("availableReplicas", 0),
        "readyReplicas": status.get("readyReplicas", 0),
        "replicas": status.get("replicas", 0),
        "images": [
            {"container": container.get("name", ""), "image": container.get("image", "")}
            for container in containers
            if container.get("image")
        ],
    }


def generic_summary(item: Any | None) -> dict[str, Any] | None:
    if not item:
        return None
    metadata = item.get("metadata", {})
    return {
        "resourceVersion": metadata.get("resourceVersion"),
        "uid": metadata.get("uid"),
        "creationTimestamp": metadata.get("creationTimestamp"),
        "type": item.get("type"),
    }


def namespace_summary(document: Any | None) -> dict[str, Any] | None:
    if not document:
        return None
    metadata = document.get("metadata", {})
    labels = metadata.get("labels", {})
    return {
        "resourceVersion": metadata.get("resourceVersion"),
        "uid": metadata.get("uid"),
        "requiredLabels": {key: labels.get(key) for key in REQUIRED_NAMESPACE_LABELS},
    }


def changed(before: dict[str, Any] | None, after: dict[str, Any] | None) -> bool:
    return before != after


def namespace_policy_ok(summary: dict[str, Any] | None) -> bool:
    if not summary:
        return False
    labels = summary.get("requiredLabels", {})
    return all(labels.get(key) == expected for key, expected in REQUIRED_NAMESPACE_LABELS.items())


def main() -> int:
    parser = argparse.ArgumentParser(description="Write deployment drift report")
    parser.add_argument("--before-deployments", required=True)
    parser.add_argument("--after-deployments", required=True)
    parser.add_argument("--before-secrets", required=True)
    parser.add_argument("--after-secrets", required=True)
    parser.add_argument("--before-configmaps", required=True)
    parser.add_argument("--after-configmaps", required=True)
    parser.add_argument("--before-namespace", required=True)
    parser.add_argument("--after-namespace", required=True)
    parser.add_argument("--release-name", required=True)
    parser.add_argument("--tls-secret-name", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    before_deployments = index_items(load_json(Path(args.before_deployments)))
    after_deployments = index_items(load_json(Path(args.after_deployments)))
    before_secrets = index_items(load_json(Path(args.before_secrets)))
    after_secrets = index_items(load_json(Path(args.after_secrets)))
    before_configmaps = index_items(load_json(Path(args.before_configmaps)))
    after_configmaps = index_items(load_json(Path(args.after_configmaps)))
    before_namespace = load_json(Path(args.before_namespace))
    after_namespace = load_json(Path(args.after_namespace))

    deployment_name = f"{args.release_name}-pqmsg-server"
    generated_secret_name = f"{args.release_name}-pqmsg-server-secret"
    generated_configmap_name = f"{args.release_name}-pqmsg-server-config"

    resources = {
        "deployment": {
            "name": deployment_name,
            "before": deployment_summary(before_deployments.get(deployment_name)),
            "after": deployment_summary(after_deployments.get(deployment_name)),
        },
        "generated_secret": {
            "name": generated_secret_name,
            "before": generic_summary(before_secrets.get(generated_secret_name)),
            "after": generic_summary(after_secrets.get(generated_secret_name)),
        },
        "generated_configmap": {
            "name": generated_configmap_name,
            "before": generic_summary(before_configmaps.get(generated_configmap_name)),
            "after": generic_summary(after_configmaps.get(generated_configmap_name)),
        },
        "tls_secret": {
            "name": args.tls_secret_name,
            "before": generic_summary(before_secrets.get(args.tls_secret_name)),
            "after": generic_summary(after_secrets.get(args.tls_secret_name)),
        },
        "namespace_policy": {
            "name": "namespace-policy",
            "before": namespace_summary(before_namespace),
            "after": namespace_summary(after_namespace),
        },
    }

    expected_change_keys = {"deployment", "generated_secret", "generated_configmap"}
    for resource in resources.values():
        resource["changed"] = changed(resource["before"], resource["after"])

    deployment_before = resources["deployment"]["before"] or {}
    deployment_after = resources["deployment"]["after"] or {}
    suspicious_changes: list[dict[str, Any]] = []
    expected_changes: list[dict[str, Any]] = []

    for key, resource in resources.items():
        if not resource["changed"]:
            resource["classification"] = "no_change"
            continue
        if key in expected_change_keys:
            resource["classification"] = "expected_managed_change"
            expected_changes.append({"resource": key, "name": resource["name"]})
            continue
        if key == "tls_secret":
            resource["classification"] = "unexpected_tls_secret_drift"
            suspicious_changes.append(
                {
                    "resource": key,
                    "name": resource["name"],
                    "reason": "TLS secret changed outside the managed release surfaces; review against the TLS rotation runbook.",
                }
            )
            continue
        if key == "namespace_policy":
            resource["classification"] = "unexpected_namespace_policy_drift"
            suspicious_changes.append(
                {
                    "resource": key,
                    "name": resource["name"],
                    "reason": "Namespace Pod Security Admission labels changed during apply; review cluster policy drift immediately.",
                }
            )
            continue

    report = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "release_name": args.release_name,
        "tls_secret_name": args.tls_secret_name,
        "resources": resources,
        "deployment_image_changed": deployment_before.get("images") != deployment_after.get("images"),
        "deployment_resource_version_changed": deployment_before.get("resourceVersion")
        != deployment_after.get("resourceVersion"),
        "namespace_policy_healthy_after": namespace_policy_ok(resources["namespace_policy"]["after"]),
        "expected_changes": expected_changes,
        "suspicious_changes": suspicious_changes,
        "suspicious_change_count": len(suspicious_changes),
    }
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

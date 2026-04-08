#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Kubernetes namespace/secret contract")
    parser.add_argument("--namespace-json", required=True)
    parser.add_argument("--secret-list-json", required=True)
    parser.add_argument("--configmap-list-json", required=True)
    parser.add_argument("--release-name", required=True)
    parser.add_argument("--tls-secret-name", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    namespace_doc = load_json(Path(args.namespace_json))
    secret_list = load_json(Path(args.secret_list_json))
    configmap_list = load_json(Path(args.configmap_list_json))

    namespace_labels = namespace_doc.get("metadata", {}).get("labels", {})
    secret_names = {
        item.get("metadata", {}).get("name", "")
        for item in secret_list.get("items", [])
        if item.get("metadata", {}).get("name")
    }
    configmap_names = {
        item.get("metadata", {}).get("name", "")
        for item in configmap_list.get("items", [])
        if item.get("metadata", {}).get("name")
    }

    checks = []
    for key, expected in REQUIRED_NAMESPACE_LABELS.items():
        actual = namespace_labels.get(key)
        checks.append(
            {
                "name": f"namespace_label_{key}",
                "passed": actual == expected,
                "details": {"expected": expected, "actual": actual},
            }
        )

    checks.extend(
        [
            {
                "name": "tls_secret_present",
                "passed": args.tls_secret_name in secret_names,
                "details": {"tls_secret_name": args.tls_secret_name, "secret_names": sorted(secret_names)},
            },
        ]
    )

    failed = [item for item in checks if not item["passed"]]
    report = {
        "passed": not failed,
        "release_name": args.release_name,
        "tls_secret_name": args.tls_secret_name,
        "observed_secret_names": sorted(secret_names),
        "observed_configmap_names": sorted(configmap_names),
        "checks": checks,
    }
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if failed:
        for item in failed:
            print(f"cluster contract failed: {item['name']} -> {item['details']}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

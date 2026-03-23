#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_module(module_name: str, relative_path: str):
    path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate live applied cluster policy")
    parser.add_argument("--deployment-manifest", required=True)
    parser.add_argument("--network-policy-manifest", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    hardened = load_module(
        "validate_hardened_manifests",
        "scripts/security/validate_hardened_manifests.py",
    )
    image_pinning = load_module(
        "validate_image_pinning",
        "scripts/security/validate_image_pinning.py",
    )
    network_policy = load_module(
        "validate_network_policy",
        "scripts/security/validate_network_policy.py",
    )

    deployment_path = Path(args.deployment_manifest)
    network_policy_path = Path(args.network_policy_manifest)

    hardened_failures = hardened.validate_manifest(deployment_path)
    image_failures = image_pinning.validate(deployment_path)
    network_failures = network_policy.validate(network_policy_path)

    report = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "passed": not (hardened_failures or image_failures or network_failures),
        "deployment_manifest": str(deployment_path),
        "network_policy_manifest": str(network_policy_path),
        "checks": [
            {
                "name": "live_hardened_manifest_policy",
                "passed": not hardened_failures,
                "failures": hardened_failures,
            },
            {
                "name": "live_image_pinning_policy",
                "passed": not image_failures,
                "failures": image_failures,
            },
            {
                "name": "live_network_policy",
                "passed": not network_failures,
                "failures": network_failures,
            },
        ],
    }

    Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

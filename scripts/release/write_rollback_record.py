#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Write rollback execution record")
    parser.add_argument("--release-manifest", required=True)
    parser.add_argument("--promotion-record", required=True)
    parser.add_argument("--rollback-image", required=True)
    parser.add_argument("--rendered-chart", required=True)
    parser.add_argument("--current-deployments-json", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--release-name", required=True)
    parser.add_argument("--environment-name", required=True)
    parser.add_argument("--deployment-mode", required=True)
    parser.add_argument("--apply", choices=["true", "false"], required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    manifest = load_json(Path(args.release_manifest))
    promotion_record = load_json(Path(args.promotion_record))
    rollback_image = Path(args.rollback_image).read_text(encoding="utf-8").strip()
    deployments = load_json(Path(args.current_deployments_json))

    observed_images: list[dict[str, str]] = []
    for item in deployments.get("items", []):
        deployment_name = item.get("metadata", {}).get("name", "")
        for container in item.get("spec", {}).get("template", {}).get("spec", {}).get("containers", []):
            image = container.get("image", "")
            if image:
                observed_images.append(
                    {
                        "deployment": deployment_name,
                        "container": container.get("name", ""),
                        "image": image,
                    }
                )

    record = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "release_tag": manifest["tag"],
        "commit_sha": manifest["commit_sha"],
        "workflow_run_id": manifest["workflow_run_id"],
        "namespace": args.namespace,
        "release_name": args.release_name,
        "environment_name": args.environment_name,
        "deployment_mode": args.deployment_mode,
        "apply_requested": args.apply == "true",
        "current_live_images": observed_images,
        "target_image": rollback_image,
        "rollback_target_image": rollback_image,
        "rollback_chart_sha256": sha256(Path(args.rendered_chart)),
        "source_promotion_target_image": promotion_record.get("target_image"),
        "source_promotion_release_tag": promotion_record.get("release_tag"),
        "source_promotion_generated_at_utc": promotion_record.get("generated_at_utc"),
        "release_bundle_manifest_sha256": sha256(Path(args.release_manifest)),
    }
    Path(args.output).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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


def split_image_ref(image: str) -> tuple[str, str | None, str | None]:
    if "@sha256:" in image:
        repository, digest = image.split("@", 1)
        return repository, None, digest
    if ":" in image.rsplit("/", 1)[-1]:
        repository, tag = image.rsplit(":", 1)
        return repository, tag, None
    return image, None, None


def load_json(path: Path | None) -> Any:
    if path is None or not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Write deployment promotion and rollback record")
    parser.add_argument("--release-manifest", required=True)
    parser.add_argument("--rendered-chart", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--rollback-image-output", required=True)
    parser.add_argument("--rollback-overrides-output", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--release-name", required=True)
    parser.add_argument("--environment-name", required=True)
    parser.add_argument("--deployment-mode", required=True)
    parser.add_argument("--apply", choices=["true", "false"], required=True)
    parser.add_argument("--current-deployments-json")
    args = parser.parse_args()

    manifest_path = Path(args.release_manifest)
    rendered_chart_path = Path(args.rendered_chart)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    target_image = manifest["container_images"][0]["immutable_ref"]

    current_deployments = load_json(
        Path(args.current_deployments_json) if args.current_deployments_json else None
    )
    observed_images: list[dict[str, str]] = []
    if current_deployments:
        for item in current_deployments.get("items", []):
            deployment_name = item.get("metadata", {}).get("name", "")
            for container in item.get("spec", {}).get("template", {}).get("spec", {}).get(
                "containers", []
            ):
                image = container.get("image", "")
                if image:
                    observed_images.append(
                        {
                            "deployment": deployment_name,
                            "container": container.get("name", ""),
                            "image": image,
                        }
                    )

    unique_images = sorted({entry["image"] for entry in observed_images})
    rollback_image = unique_images[0] if len(unique_images) == 1 else None

    rollback_image_path = Path(args.rollback_image_output)
    rollback_overrides_path = Path(args.rollback_overrides_output)
    if rollback_image:
        rollback_image_path.write_text(rollback_image + "\n", encoding="utf-8")
        repository, tag, digest = split_image_ref(rollback_image)
        lines = ["image:", f"  repository: {repository}"]
        if digest:
            lines.append(f"  digest: {digest}")
        elif tag:
            lines.append(f"  tag: {tag}")
        rollback_overrides_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        rollback_image_path.write_text("", encoding="utf-8")
        rollback_overrides_path.write_text(
            "# rollback image unavailable: no live deployment found or multiple images observed\n",
            encoding="utf-8",
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
        "target_image": target_image,
        "target_chart_sha256": sha256(rendered_chart_path),
        "observed_live_images": observed_images,
        "rollback_image": rollback_image,
        "rollback_ready": rollback_image is not None,
        "release_bundle_manifest_sha256": sha256(manifest_path),
    }
    Path(args.output).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

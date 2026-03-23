#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path


REQUIRED = {
    "promote": {
        "path": ".github/workflows/promote.yml",
        "permission_contents": [
            "permissions:",
            "contents: read",
            "id-token: write",
            "attestations: write",
            "issues: write",
        ],
        "ordered_contents": [
            "- name: write promotion bundle manifest",
            "dist/promotion-bundle-manifest.json",
            "- name: attest promotion bundle manifest provenance",
            "uses: actions/attest@v4",
            "subject-path: dist/promotion-bundle-manifest.json",
            "- name: upload promotion bundle",
        ],
    },
    "rollback": {
        "path": ".github/workflows/rollback.yml",
        "permission_contents": [
            "permissions:",
            "contents: read",
            "id-token: write",
            "attestations: write",
            "issues: write",
        ],
        "ordered_contents": [
            "- name: download promotion bundle",
            "- name: verify promotion bundle",
            "verify_workflow_bundle.sh promotion dist",
            "- name: write rollback bundle manifest",
            "dist/rollback-bundle-manifest.json",
            "- name: attest rollback bundle manifest provenance",
            "uses: actions/attest@v4",
            "subject-path: dist/rollback-bundle-manifest.json",
            "- name: upload rollback bundle",
        ],
    },
}


def validate(label: str, root: Path) -> list[str]:
    spec = REQUIRED[label]
    path = root / spec["path"]
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []

    for item in spec["permission_contents"]:
        if item not in text:
            errors.append(f"{path}: missing required content `{item}`")

    last_index = -1
    for item in spec["ordered_contents"]:
        idx = text.find(item)
        if idx == -1:
            errors.append(f"{path}: missing required ordered content `{item}`")
            continue
        if idx < last_index:
            errors.append(f"{path}: content `{item}` appears out of order")
        last_index = idx

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate release-governance workflow policy")
    parser.add_argument("--root", default=".")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    errors: list[str] = []
    for label in ("promote", "rollback"):
        errors.extend(validate(label, root))

    if errors:
        for item in errors:
            print(item)
        return 1

    print("release governance workflow policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

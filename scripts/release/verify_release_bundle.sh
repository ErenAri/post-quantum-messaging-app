#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <dist-dir> [owner/repo]" >&2
  exit 1
fi

dist_dir="$1"
repo="${2:-}"

if [[ ! -d "$dist_dir" ]]; then
  echo "release dist directory not found: $dist_dir" >&2
  exit 1
fi

required_files=(
  "pqmsg-server-linux-x86_64"
  "sbom.tar.gz"
  "release-manifest.json"
  "release-security-posture.json"
  "container-image.txt"
  "helm-image-overrides.yaml"
  "checksums.txt"
)

for file in "${required_files[@]}"; do
  if [[ ! -f "$dist_dir/$file" ]]; then
    echo "missing release artifact: $dist_dir/$file" >&2
    exit 1
  fi
done

sha256sum --check < "$dist_dir/checksums.txt"

python - "$dist_dir/release-manifest.json" <<'PY'
import json
import re
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
images = manifest.get("container_images") or []
if not images:
    raise SystemExit("release manifest does not contain any container image records")
for image in images:
    name = image.get("name", "")
    digest = image.get("digest", "")
    immutable_ref = image.get("immutable_ref", "")
    if not name:
        raise SystemExit("release manifest container image is missing name")
    if not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
        raise SystemExit(f"release manifest container image has invalid digest: {digest}")
    if immutable_ref != f"{name}@{digest}":
        raise SystemExit(f"release manifest container image has invalid immutable_ref: {immutable_ref}")

container_ref = Path(sys.argv[2]).read_text(encoding="utf-8").strip()
if container_ref != images[0]["immutable_ref"]:
    raise SystemExit("container-image.txt does not match release manifest immutable_ref")

helm_overrides = Path(sys.argv[3]).read_text(encoding="utf-8")
if f"repository: {images[0]['name']}" not in helm_overrides:
    raise SystemExit("helm-image-overrides.yaml does not contain the manifest image repository")
if f"digest: {images[0]['digest']}" not in helm_overrides:
    raise SystemExit("helm-image-overrides.yaml does not contain the manifest image digest")

posture = json.loads(Path(sys.argv[4]).read_text(encoding="utf-8"))
support_matrix = posture.get("support_matrix") or {}
audit_findings = posture.get("audit_findings") or {}
release_audit_gate = posture.get("release_audit_gate") or {}
if not support_matrix.get("path") or not support_matrix.get("sha256"):
    raise SystemExit("release-security-posture.json is missing support matrix evidence")
if not audit_findings.get("path") or not audit_findings.get("sha256"):
    raise SystemExit("release-security-posture.json is missing audit findings evidence")
if "blocking_findings" not in release_audit_gate:
    raise SystemExit("release-security-posture.json is missing release audit gate details")
if release_audit_gate.get("blocking_findings"):
    raise SystemExit("release-security-posture.json contains blocking release audit findings")
PY
"$dist_dir/container-image.txt" "$dist_dir/helm-image-overrides.yaml" "$dist_dir/release-security-posture.json"

if [[ -n "$repo" ]]; then
  if ! command -v gh >/dev/null 2>&1; then
    echo "gh CLI not found; skipping attestation verification" >&2
    exit 0
  fi
  gh attestation verify "$dist_dir/pqmsg-server-linux-x86_64" -R "$repo"
  gh attestation verify "$dist_dir/release-manifest.json" -R "$repo"
  gh attestation verify "$dist_dir/release-security-posture.json" -R "$repo"
  gh attestation verify "$dist_dir/sbom.tar.gz" -R "$repo"
fi

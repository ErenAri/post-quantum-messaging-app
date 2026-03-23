#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: $0 <release-tag> <dist-dir> [owner/repo]" >&2
  exit 1
fi

release_tag="$1"
dist_dir="$2"
repo="${3:-}"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI not found" >&2
  exit 1
fi

mkdir -p "$dist_dir"

cmd=(
  gh release download "$release_tag"
  --dir "$dist_dir"
  --clobber
  --pattern "pqmsg-server-linux-x86_64"
  --pattern "sbom.tar.gz"
  --pattern "release-manifest.json"
  --pattern "container-image.txt"
  --pattern "helm-image-overrides.yaml"
  --pattern "checksums.txt"
  --pattern "checksums.txt.sig"
  --pattern "checksums.txt.pem"
)

if [[ -n "$repo" ]]; then
  cmd+=(-R "$repo")
fi

"${cmd[@]}"

#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 || $# -gt 5 ]]; then
  echo "usage: $0 <promotion-run-id> <release-tag> <deployment-mode> <dist-dir> [owner/repo]" >&2
  exit 1
fi

promotion_run_id="$1"
release_tag="$2"
deployment_mode="$3"
dist_dir="$4"
repo="${5:-}"
artifact_name="promotion-bundle-${release_tag}-${deployment_mode}"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI not found" >&2
  exit 1
fi

mkdir -p "$dist_dir"

cmd=(
  gh run download "$promotion_run_id"
  --dir "$dist_dir"
  --name "$artifact_name"
)

if [[ -n "$repo" ]]; then
  cmd+=(-R "$repo")
fi

"${cmd[@]}"

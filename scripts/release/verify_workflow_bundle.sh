#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: $0 <promotion|rollback> <dist-dir> [owner/repo]" >&2
  exit 1
fi

bundle_kind="$1"
dist_dir="$2"
repo="${3:-}"

cmd=(
  python scripts/release/verify_workflow_bundle.py
  --bundle-kind "$bundle_kind"
  --dist-dir "$dist_dir"
)

if [[ -n "$repo" ]]; then
  cmd+=(--repo "$repo")
fi

"${cmd[@]}"

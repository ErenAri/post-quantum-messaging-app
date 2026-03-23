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
  "checksums.txt"
)

for file in "${required_files[@]}"; do
  if [[ ! -f "$dist_dir/$file" ]]; then
    echo "missing release artifact: $dist_dir/$file" >&2
    exit 1
  fi
done

(cd "$dist_dir" && sha256sum --check checksums.txt)

if [[ -n "$repo" ]]; then
  if ! command -v gh >/dev/null 2>&1; then
    echo "gh CLI not found; skipping attestation verification" >&2
    exit 0
  fi
  gh attestation verify "$dist_dir/pqmsg-server-linux-x86_64" -R "$repo"
  gh attestation verify "$dist_dir/release-manifest.json" -R "$repo"
  gh attestation verify "$dist_dir/sbom.tar.gz" -R "$repo"
fi

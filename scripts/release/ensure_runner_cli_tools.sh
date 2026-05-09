#!/usr/bin/env bash
set -euo pipefail

HELM_VERSION="${HELM_VERSION:-v3.18.4}"
KUBECTL_VERSION="${KUBECTL_VERSION:-v1.34.1}"
KIND_VERSION="${KIND_VERSION:-v0.29.0}"
LOCAL_BIN="${HOME}/.local/bin"

mkdir -p "${LOCAL_BIN}"
export PATH="${LOCAL_BIN}:${PATH}"

if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "${LOCAL_BIN}" >> "${GITHUB_PATH}"
fi

download_with_retries() {
  local url="$1"
  local output="$2"
  curl -fL \
    --retry 5 \
    --retry-delay 5 \
    --retry-all-errors \
    --connect-timeout 20 \
    --max-time 300 \
    "${url}" \
    -o "${output}"
}

if ! command -v helm >/dev/null 2>&1; then
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir}"' EXIT
  download_with_retries \
    "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" \
    "${tmpdir}/helm.tgz"
  tar -xzf "${tmpdir}/helm.tgz" -C "${tmpdir}"
  install "${tmpdir}/linux-amd64/helm" "${LOCAL_BIN}/helm"
fi

if ! command -v kubectl >/dev/null 2>&1; then
  download_with_retries \
    "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
    "${LOCAL_BIN}/kubectl"
  chmod +x "${LOCAL_BIN}/kubectl"
fi

if ! command -v kind >/dev/null 2>&1; then
  download_with_retries \
    "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64" \
    "${LOCAL_BIN}/kind"
  chmod +x "${LOCAL_BIN}/kind"
fi

helm version --short
kubectl version --client
kind version

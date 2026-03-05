#!/usr/bin/env bash
set -euo pipefail

MODEL_PATH="${1:-verification/proverif/pqxdh_hybrid_model.pv}"

if ! command -v proverif >/dev/null 2>&1; then
  echo "proverif executable not found in PATH"
  exit 1
fi

proverif "$MODEL_PATH"

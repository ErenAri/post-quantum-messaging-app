#!/usr/bin/env bash
set -euo pipefail

run_tests=0
if [[ "${1:-}" == "--run-tests" ]]; then
  run_tests=1
fi

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

print_check() {
  local ok="$1"
  local label="$2"
  local detail="$3"
  if [[ "$ok" == "1" ]]; then
    echo "[OK] $label: $detail"
  else
    echo "[MISSING] $label: $detail"
  fi
}

platform="$(uname -s)"
case "$platform" in
  Linux*)
    echo "Checking Linux SQLCipher server prerequisites..."
    pkg_ok=0; has_cmd pkg-config && pkg_ok=1
    perl_ok=0; has_cmd perl && perl_ok=1
    make_ok=0; has_cmd make && make_ok=1
    openssl_pkg_ok=0
    if [[ "$pkg_ok" == "1" ]] && pkg-config --exists openssl; then
      openssl_pkg_ok=1
    fi
    print_check "$pkg_ok" "pkg-config" "required for OpenSSL discovery"
    print_check "$perl_ok" "perl" "needed if vendored OpenSSL is used"
    print_check "$make_ok" "make" "build prerequisite"
    print_check "$openssl_pkg_ok" "openssl pkg-config" "requires OpenSSL development package"
    if [[ "$pkg_ok" != "1" || "$make_ok" != "1" || "$openssl_pkg_ok" != "1" ]]; then
      echo "Missing Linux SQLCipher prerequisites." >&2
      exit 1
    fi
    ;;
  Darwin*)
    echo "Checking macOS SQLCipher server prerequisites..."
    brew_ok=0; has_cmd brew && brew_ok=1
    perl_ok=0; has_cmd perl && perl_ok=1
    make_ok=0; has_cmd make && make_ok=1
    openssl_ok=0
    if [[ "$brew_ok" == "1" ]] && brew --prefix openssl@3 >/dev/null 2>&1; then
      openssl_ok=1
    fi
    print_check "$brew_ok" "brew" "used to install OpenSSL"
    print_check "$perl_ok" "perl" "needed if vendored OpenSSL is used"
    print_check "$make_ok" "make" "build prerequisite"
    print_check "$openssl_ok" "openssl@3" "expected via Homebrew"
    if [[ "$brew_ok" != "1" || "$make_ok" != "1" || "$openssl_ok" != "1" ]]; then
      echo "Missing macOS SQLCipher prerequisites." >&2
      exit 1
    fi
    ;;
  *)
    echo "Use scripts/dev/check_sqlcipher_server_prereqs.ps1 on Windows." >&2
    exit 1
    ;;
esac

if [[ "$run_tests" == "1" ]]; then
  cargo test -p pqmsg-server 'db::tests::sqlite_' --lib
fi

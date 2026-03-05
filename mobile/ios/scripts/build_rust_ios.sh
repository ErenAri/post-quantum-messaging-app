#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${IOS_DIR}/../.." && pwd)"
GEN_DIR="${IOS_DIR}/PQMsgDemo/Generated"
FRAMEWORK_DIR="${IOS_DIR}/Frameworks"

mkdir -p "${GEN_DIR}"
mkdir -p "${FRAMEWORK_DIR}"

cd "${REPO_ROOT}"

rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

cargo build -p pqmsg-ios --release --target aarch64-apple-ios --features pqmsg-core/pq-oqs
cargo build -p pqmsg-ios --release --target aarch64-apple-ios-sim --features pqmsg-core/pq-oqs
cargo build -p pqmsg-ios --release --target x86_64-apple-ios --features pqmsg-core/pq-oqs

cargo run -p pqmsg-ios --bin uniffi-bindgen -- generate \
  --library target/aarch64-apple-ios/release/libpqmsg_ios.a \
  --language swift \
  --out-dir "${GEN_DIR}"

rm -rf "${FRAMEWORK_DIR}/pqmsg_iosFFI.xcframework"

xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libpqmsg_ios.a -headers "${GEN_DIR}" \
  -library target/aarch64-apple-ios-sim/release/libpqmsg_ios.a -headers "${GEN_DIR}" \
  -library target/x86_64-apple-ios/release/libpqmsg_ios.a -headers "${GEN_DIR}" \
  -output "${FRAMEWORK_DIR}/pqmsg_iosFFI.xcframework"

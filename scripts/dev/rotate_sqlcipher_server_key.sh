#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DATABASE_URL="${PQMSG_DATABASE_URL:-}"
FROM_KEY_B64="${PQMSG_SQLITE_ROTATE_FROM_KEY_B64:-}"
TO_KEY_B64="${PQMSG_SQLITE_ENCRYPTION_KEY_B64:-}"
CIPHER_COMPATIBILITY="${PQMSG_SQLITE_CIPHER_COMPATIBILITY:-}"
CIPHER_PAGE_SIZE="${PQMSG_SQLITE_CIPHER_PAGE_SIZE:-}"
GENERATE_TARGET_KEY="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --database-url)
      DATABASE_URL="$2"
      shift 2
      ;;
    --from-key-b64)
      FROM_KEY_B64="$2"
      shift 2
      ;;
    --to-key-b64)
      TO_KEY_B64="$2"
      shift 2
      ;;
    --cipher-compatibility)
      CIPHER_COMPATIBILITY="$2"
      shift 2
      ;;
    --cipher-page-size)
      CIPHER_PAGE_SIZE="$2"
      shift 2
      ;;
    --generate-target-key)
      GENERATE_TARGET_KEY="true"
      shift
      ;;
    -h|--help)
      cat <<'EOF'
Usage: scripts/dev/rotate_sqlcipher_server_key.sh \
  --database-url <sqlite-url> \
  --from-key-b64 <base64-current-32-byte-key> \
  [--to-key-b64 <base64-target-32-byte-key> | --generate-target-key] \
  [--cipher-compatibility <1..4>] \
  [--cipher-page-size <512..65536-power-of-two>]
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$DATABASE_URL" ]]; then
  echo "Provide --database-url or set PQMSG_DATABASE_URL." >&2
  exit 1
fi
if [[ -z "$FROM_KEY_B64" ]]; then
  echo "Provide --from-key-b64 or set PQMSG_SQLITE_ROTATE_FROM_KEY_B64." >&2
  exit 1
fi
if [[ "$GENERATE_TARGET_KEY" == "true" && -n "$TO_KEY_B64" ]]; then
  echo "Use either --generate-target-key or --to-key-b64, not both." >&2
  exit 1
fi
if [[ "$GENERATE_TARGET_KEY" == "true" ]]; then
  TO_KEY_B64="$(openssl rand -base64 32 | tr -d '\n')"
fi
if [[ -z "$TO_KEY_B64" ]]; then
  echo "Provide --to-key-b64, set PQMSG_SQLITE_ENCRYPTION_KEY_B64, or use --generate-target-key." >&2
  exit 1
fi

"$SCRIPT_DIR/check_sqlcipher_server_prereqs.sh"

args=(
  run -p pqmsg-server --bin sqlite_rotate_key --
  --database-url "$DATABASE_URL"
  --from-key-b64 "$FROM_KEY_B64"
  --to-key-b64 "$TO_KEY_B64"
)
if [[ -n "$CIPHER_COMPATIBILITY" ]]; then
  args+=(--cipher-compatibility "$CIPHER_COMPATIBILITY")
fi
if [[ -n "$CIPHER_PAGE_SIZE" ]]; then
  args+=(--cipher-page-size "$CIPHER_PAGE_SIZE")
fi

echo "Running offline SQLite SQLCipher key rotation..."
echo "Database URL: $DATABASE_URL"
cargo "${args[@]}"

echo
echo "Rotation finished. Update the server secret/config to use only the new key:"
echo "PQMSG_SQLITE_ENCRYPTION_KEY_B64=$TO_KEY_B64"

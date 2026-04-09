#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <bundle.tar.gz> <release-id> <domain>" >&2
  exit 1
fi

BUNDLE_PATH="$1"
RELEASE_ID="$2"
DOMAIN="$3"

WEB_ROOT="${WEB_ROOT:-/var/www/pqmsg-web}"
NGINX_AVAILABLE_DIR="${NGINX_AVAILABLE_DIR:-/etc/nginx/sites-available}"
NGINX_ENABLED_DIR="${NGINX_ENABLED_DIR:-/etc/nginx/sites-enabled}"
NGINX_CONF_NAME="${NGINX_CONF_NAME:-pqmsg-web.conf}"
INSTALL_NGINX_CONFIG="${INSTALL_NGINX_CONFIG:-1}"
RELOAD_NGINX="${RELOAD_NGINX:-1}"

if [[ ! -f "$BUNDLE_PATH" ]]; then
  echo "bundle not found: $BUNDLE_PATH" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

tar -xzf "$BUNDLE_PATH" -C "$TMP_DIR"
BUNDLE_ROOT="$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
if [[ -z "$BUNDLE_ROOT" ]]; then
  echo "bundle root not found after extraction" >&2
  exit 1
fi

SITE_DIR="$BUNDLE_ROOT/site"
NGINX_TEMPLATE="$BUNDLE_ROOT/nginx/pqmsg-web.conf"
RELEASE_DIR="$WEB_ROOT/releases/$RELEASE_ID"
CURRENT_LINK="$WEB_ROOT/current"

if [[ ! -f "$SITE_DIR/index.html" ]]; then
  echo "bundle is missing site/index.html" >&2
  exit 1
fi

mkdir -p "$WEB_ROOT/releases"
mkdir -p "$RELEASE_DIR"

if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete "$SITE_DIR"/ "$RELEASE_DIR"/
else
  rm -rf "$RELEASE_DIR"
  mkdir -p "$RELEASE_DIR"
  cp -a "$SITE_DIR"/. "$RELEASE_DIR"/
fi

ln -sfn "$RELEASE_DIR" "$CURRENT_LINK"

if [[ "$INSTALL_NGINX_CONFIG" == "1" ]]; then
  mkdir -p "$NGINX_AVAILABLE_DIR" "$NGINX_ENABLED_DIR"
  sed \
    -e "s|pqmsg.example.com|$DOMAIN|g" \
    -e "s|/var/www/pqmsg-web/current|$CURRENT_LINK|g" \
    "$NGINX_TEMPLATE" > "$NGINX_AVAILABLE_DIR/$NGINX_CONF_NAME"
  ln -sfn "$NGINX_AVAILABLE_DIR/$NGINX_CONF_NAME" "$NGINX_ENABLED_DIR/$NGINX_CONF_NAME"
fi

nginx -t

if [[ "$RELOAD_NGINX" == "1" ]]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl reload nginx
  else
    service nginx reload
  fi
fi

echo "Deployed release $RELEASE_ID to $CURRENT_LINK"
echo "Verify with: curl -I https://$DOMAIN/ && curl -I https://$DOMAIN/manifest.webmanifest"

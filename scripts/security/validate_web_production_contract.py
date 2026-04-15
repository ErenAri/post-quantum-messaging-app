from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "mobile" / "web" / "public" / "manifest.webmanifest"
INDEX_PATH = ROOT / "mobile" / "web" / "index.html"
HEADERS_PATH = ROOT / "mobile" / "web" / "securityHeaders.ts"
NGINX_PATH = ROOT / "deploy" / "web" / "nginx" / "pqmsg-web.conf"
PAGES_HEADERS_PATH = ROOT / "mobile" / "web" / "public" / "_headers"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    require("demo" not in manifest["name"].lower(), "manifest name must not advertise demo-only branding")
    require(
        "demo" not in manifest["short_name"].lower(),
        "manifest short_name must not advertise demo-only branding",
    )
    require(manifest["theme_color"].lower() == "#2d6cf6", "manifest theme_color must match production brand")
    require(
        all("maskable" in icon.get("purpose", "") for icon in manifest["icons"]),
        "manifest icons must advertise maskable support",
    )

    index_html = INDEX_PATH.read_text(encoding="utf-8")
    require("Content-Security-Policy" not in index_html, "index.html must not bake environment-specific CSP")
    require("<title>PQmsg</title>" in index_html, "index.html title must use production branding")

    header_source = HEADERS_PATH.read_text(encoding="utf-8")
    require("Strict-Transport-Security" in header_source, "production header contract must include HSTS")
    require("http://127.0.0.1:*" in header_source, "development header contract must keep loopback exceptions")
    require(
        'const PRODUCTION_CONNECT_SRC = ["\'self\'", "https:", "wss:"]' in header_source,
        "production connect-src must stay HTTPS/WSS only",
    )

    nginx = NGINX_PATH.read_text(encoding="utf-8")
    for required in (
        "Strict-Transport-Security",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Permissions-Policy",
        "connect-src 'self' https: wss:",
        "try_files $uri $uri/ /index.html;",
        "location = /sw.js",
        "location = /manifest.webmanifest",
        "immutable",
    ):
        require(required in nginx, f"nginx production config is missing: {required}")

    require("ws://localhost" not in nginx, "nginx production CSP must not allow loopback websocket origins")
    require("http://localhost" not in nginx, "nginx production CSP must not allow loopback HTTP origins")

    pages_headers = PAGES_HEADERS_PATH.read_text(encoding="utf-8")
    for required in (
        "Content-Security-Policy:",
        "connect-src 'self' https: wss:",
        "Cross-Origin-Embedder-Policy: require-corp",
        "Cross-Origin-Opener-Policy: same-origin",
        "Cross-Origin-Resource-Policy: same-origin",
        "/index.html",
        "/manifest.webmanifest",
        "/sw.js",
        "/assets/*",
        "immutable",
    ):
        require(required in pages_headers, f"pages _headers config is missing: {required}")


if __name__ == "__main__":
    main()

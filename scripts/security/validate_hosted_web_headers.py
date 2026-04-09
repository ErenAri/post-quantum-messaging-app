from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.parse
import urllib.request


ASSET_RE = re.compile(r'/(assets/[^"\']+)')


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a hosted PQmsg web shell for production header and caching requirements."
    )
    parser.add_argument("--base-url", required=True)
    parser.add_argument(
        "--allow-http-loopback",
        action="store_true",
        help="Allow http://127.0.0.1 or http://localhost targets for local validation.",
    )
    return parser.parse_args()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def fetch(url: str) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers.items()), error.read()


def normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key.lower(): value for key, value in headers.items()}


def main() -> None:
    args = parse_args()
    base_url = args.base_url.rstrip("/")
    parsed = urllib.parse.urlparse(base_url)
    require(parsed.scheme in {"https", "http"}, "base url must use http or https")

    is_loopback_http = parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}
    require(
        parsed.scheme == "https" or (args.allow_http_loopback and is_loopback_http),
        "production validation requires https unless --allow-http-loopback is set for localhost",
    )

    summary: dict[str, object] = {"base_url": base_url}

    status, headers, body = fetch(f"{base_url}/")
    headers = normalize_headers(headers)
    require(status == 200, f"root path returned {status}")
    require("no-store" in headers.get("cache-control", ""), "root path must be no-store")
    require("default-src 'self'" in headers.get("content-security-policy", ""), "CSP default-src must be self")
    require("connect-src 'self' https: wss:" in headers.get("content-security-policy", ""), "CSP connect-src must be self https wss")
    require(headers.get("cross-origin-opener-policy") == "same-origin", "COOP must be same-origin")
    require(headers.get("cross-origin-embedder-policy") == "require-corp", "COEP must be require-corp")
    require(headers.get("cross-origin-resource-policy") == "same-origin", "CORP must be same-origin")
    require(headers.get("x-content-type-options") == "nosniff", "X-Content-Type-Options must be nosniff")
    require(headers.get("referrer-policy") == "no-referrer", "Referrer-Policy must be no-referrer")
    require(headers.get("x-frame-options") == "DENY", "X-Frame-Options must be DENY")
    require("permissions-policy" in headers, "Permissions-Policy header must be present")
    if parsed.scheme == "https":
        require("strict-transport-security" in headers, "HSTS header must be present on https")
    summary["root_headers"] = headers

    html = body.decode("utf-8", errors="replace")
    asset_match = ASSET_RE.search(html)
    require(asset_match is not None, "could not locate hashed /assets/* path in index.html")
    asset_path = f"/{asset_match.group(1).lstrip('/')}"
    summary["asset_path"] = asset_path

    status, headers, _ = fetch(f"{base_url}/manifest.webmanifest")
    headers = normalize_headers(headers)
    require(status == 200, f"manifest returned {status}")
    require("no-cache" in headers.get("cache-control", ""), "manifest must be no-cache")
    require("application/manifest" in headers.get("content-type", ""), "manifest content-type must be application/manifest+json")
    summary["manifest_headers"] = headers

    status, headers, _ = fetch(f"{base_url}/sw.js")
    headers = normalize_headers(headers)
    require(status == 200, f"service worker returned {status}")
    cache_control = headers.get("cache-control", "")
    require("no-cache" in cache_control and "no-store" in cache_control, "sw.js must be no-cache and no-store")
    summary["sw_headers"] = headers

    status, headers, _ = fetch(urllib.parse.urljoin(f"{base_url}/", asset_path.lstrip("/")))
    headers = normalize_headers(headers)
    require(status == 200, f"hashed asset returned {status}")
    require("immutable" in headers.get("cache-control", ""), "hashed assets must be immutable")
    summary["asset_headers"] = headers

    status, _, _ = fetch(f"{base_url}/metrics")
    require(status == 404, f"/metrics must not be exposed on hosted web origin (got {status})")
    status, _, _ = fetch(f"{base_url}/assets/definitely-missing.js")
    require(status == 404, f"missing asset path must return 404 (got {status})")

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

from __future__ import annotations

import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SUPPORT_MATRIX_PATH = REPO_ROOT / "docs" / "SUPPORT_MATRIX.json"
README_PATH = REPO_ROOT / "README.md"
WEB_DOC_PATH = REPO_ROOT / "docs" / "WEB.md"
API_DOC_PATH = REPO_ROOT / "docs" / "API.md"


def main() -> int:
    matrix = json.loads(SUPPORT_MATRIX_PATH.read_text(encoding="utf-8"))
    failures: list[str] = []

    if matrix.get("version") != 1:
        failures.append("docs/SUPPORT_MATRIX.json must set version = 1")

    current = matrix.get("current_beta_scope")
    if not isinstance(current, dict):
        failures.append("docs/SUPPORT_MATRIX.json current_beta_scope must be an object")
        current = {}

    expected = {
        "summary": "Android private beta for messaging only",
        "supported_beta_clients": ["android"],
        "web_client_policy": "demo_only",
        "calling_supported": False,
        "group_messaging_supported": False,
        "private_group_messaging_supported": True,
        "manual_contact_bootstrap": ["@username", "opaque_invite"],
        "private_contact_discovery_service_contract": "attested_enclave_v1",
        "private_contact_discovery_allowed_deployments": ["development", "pilot", "production"],
    }
    for key, value in expected.items():
        if current.get(key) != value:
            failures.append(f"docs/SUPPORT_MATRIX.json current_beta_scope.{key} must be {value!r}")

    readme_text = README_PATH.read_text(encoding="utf-8")
    web_text = WEB_DOC_PATH.read_text(encoding="utf-8")
    api_text = API_DOC_PATH.read_text(encoding="utf-8")

    readme_required = [
        "Android private beta for messaging only",
        "Web remains a demo surface and is not part of the supported beta.",
        "`supported_beta_clients`",
        "`web_client_policy = demo_only`",
        "Canonical machine-readable support posture now lives in `docs/SUPPORT_MATRIX.json`.",
    ]
    for snippet in readme_required:
        if snippet not in readme_text:
            failures.append(f"README.md missing support-matrix snippet: {snippet}")

    web_required = [
        "Android is the supported messaging beta client.",
        "Web remains demo-only.",
        "`supported_beta_clients`",
        "`web_client_policy = demo_only`",
        "`docs/SUPPORT_MATRIX.json`",
    ]
    for snippet in web_required:
        if snippet not in web_text:
            failures.append(f"docs/WEB.md missing support-matrix snippet: {snippet}")

    api_required = [
        '"supported_beta_clients": ["android"]',
        '"web_client_policy": "demo_only"',
        '"group_messaging_supported": false',
        '"private_group_messaging_supported": true',
        "docs/SUPPORT_MATRIX.json",
    ]
    for snippet in api_required:
        if snippet not in api_text:
            failures.append(f"docs/API.md missing support-matrix snippet: {snippet}")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print(f"{SUPPORT_MATRIX_PATH}: support matrix validated against README.md, docs/WEB.md, and docs/API.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

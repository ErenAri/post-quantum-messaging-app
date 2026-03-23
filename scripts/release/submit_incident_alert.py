#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, parse, request


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_alertmanager_api(url: str) -> str:
    raw = url.strip().rstrip("/")
    if not raw:
        return ""
    if raw.endswith("/api/v2/alerts"):
        return raw
    return raw + "/api/v2/alerts"


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def base_report(operation: str, endpoint: str, incident_required: bool) -> dict[str, Any]:
    return {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "operation": operation,
        "incident_required": incident_required,
        "endpoint": endpoint,
        "attempted": False,
        "submitted": False,
        "status_code": None,
        "outcome": "unknown",
        "error": None,
        "response_body": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Submit incident alert and record delivery evidence")
    parser.add_argument("--operation", choices=["promote", "rollback"], required=True)
    parser.add_argument("--failure-handoff", required=True)
    parser.add_argument("--payload-json", required=True)
    parser.add_argument("--alertmanager-api-url", default="")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    handoff = load_json(Path(args.failure_handoff))
    incident_required = bool(handoff.get("incident_required"))
    endpoint = normalize_alertmanager_api(args.alertmanager_api_url)
    report = base_report(args.operation, endpoint, incident_required)
    output = Path(args.output)

    if not incident_required:
        report["outcome"] = "not_required"
        write_report(output, report)
        return 0

    if not endpoint:
        report["outcome"] = "not_configured"
        write_report(output, report)
        return 0

    payload_path = Path(args.payload_json)
    if not payload_path.is_file():
        report["outcome"] = "payload_missing"
        report["error"] = f"missing payload: {payload_path}"
        write_report(output, report)
        return 1

    payload = payload_path.read_bytes()
    http_request = request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    report["attempted"] = True

    try:
        with request.urlopen(http_request, timeout=15) as response:
            body = response.read().decode("utf-8", errors="replace")
            report["submitted"] = True
            report["status_code"] = getattr(response, "status", None)
            report["response_body"] = body[:4096]
            report["outcome"] = "submitted"
            write_report(output, report)
            return 0
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        report["status_code"] = exc.code
        report["error"] = str(exc)
        report["response_body"] = body[:4096]
        report["outcome"] = "http_error"
        write_report(output, report)
        return 1
    except Exception as exc:  # pragma: no cover - defensive wrapper
        report["error"] = repr(exc)
        report["outcome"] = "submission_error"
        write_report(output, report)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

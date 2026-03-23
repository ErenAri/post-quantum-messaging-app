#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, parse, request

from incident_issue_labels import apply_resolution_labels, resolution_label_specs


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def api_request(
    method: str,
    url: str,
    token: str,
    payload: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any] | list[Any] | str]:
    data = None
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "pqmsg-release-governance",
    }
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = request.Request(url, data=data, headers=headers, method=method)
    try:
        with request.urlopen(req, timeout=20) as response:
            body = response.read().decode("utf-8", errors="replace")
            if not body:
                return response.status, ""
            return response.status, json.loads(body)
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body) if body else ""
        except Exception:
            parsed = body
        raise RuntimeError(json.dumps({"status": exc.code, "body": parsed}))


def parse_error_status(exc: Exception) -> int | None:
    try:
        payload = json.loads(str(exc))
    except Exception:
        return None
    status = payload.get("status")
    return int(status) if isinstance(status, int) else None


def build_scope_key(record: dict[str, Any]) -> str:
    context = record.get("record_context", {}) or {}
    return "|".join(
        [
            str(context.get("environment_name", "unknown")),
            str(context.get("deployment_mode", "unknown")),
            str(context.get("namespace", "unknown")),
            str(context.get("release_name", "unknown")),
        ]
    )


def build_comment(
    record: dict[str, Any],
    repository: str,
    run_id: str,
    workflow_name: str,
) -> str:
    context = record.get("record_context", {}) or {}
    operation = record.get("operation", "unknown")
    release_tag = context.get("release_tag", "unknown")
    deployment_mode = context.get("deployment_mode", "unknown")
    bundle_name = f"{operation}-bundle-{release_tag}-{deployment_mode}"
    return "\n".join(
        [
            f"Resolved by successful `{operation}` workflow.",
            "",
            f"- Release tag: `{release_tag}`",
            f"- Workflow: `{workflow_name}`",
            f"- Workflow run: https://github.com/{repository}/actions/runs/{run_id}",
            f"- Evidence bundle artifact: `{bundle_name}`",
        ]
    ) + "\n"


def find_scope_issues(api_url: str, repo: str, token: str, scope_key: str) -> list[dict[str, Any]]:
    encoded_repo = parse.quote(repo, safe="/")
    status, body = api_request(
        "GET",
        f"{api_url}/repos/{encoded_repo}/issues?state=open&per_page=100",
        token,
    )
    if status != 200 or not isinstance(body, list):
        return []
    marker = f"pqmsg-incident-scope: {scope_key}"
    results: list[dict[str, Any]] = []
    for item in body:
        if item.get("pull_request"):
            continue
        issue_body = item.get("body", "") or ""
        if marker in issue_body:
            results.append(item)
    return results


def ensure_labels(
    api_url: str,
    repo: str,
    token: str,
    label_specs: list[dict[str, str]],
) -> None:
    encoded_repo = parse.quote(repo, safe="/")
    base_url = api_url.rstrip("/")
    for spec in label_specs:
        encoded_name = parse.quote(spec["name"], safe="")
        try:
            api_request(
                "GET",
                f"{base_url}/repos/{encoded_repo}/labels/{encoded_name}",
                token,
            )
            continue
        except Exception as exc:
            status = parse_error_status(exc)
            if status != 404:
                raise
        try:
            api_request(
                "POST",
                f"{base_url}/repos/{encoded_repo}/labels",
                token,
                spec,
            )
        except Exception as exc:
            status = parse_error_status(exc)
            if status != 422:
                raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve open incident issues for a successful remediation run")
    parser.add_argument("--failure-handoff", required=True)
    parser.add_argument("--repo", default="")
    parser.add_argument("--github-api-url", required=True)
    parser.add_argument("--github-repository", required=True)
    parser.add_argument("--github-run-id", required=True)
    parser.add_argument("--github-workflow", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    record = load_json(Path(args.failure_handoff))
    repo = args.repo.strip()
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    output = Path(args.output)

    report = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "incident_required": bool(record.get("incident_required")),
        "repo": repo,
        "attempted": False,
        "resolved": False,
        "outcome": "unknown",
        "scope_key": build_scope_key(record),
        "resolved_issues": [],
        "resolved_labels": [],
        "error": None,
    }

    if report["incident_required"]:
        report["outcome"] = "still_open"
        write_report(output, report)
        return 0
    if not repo:
        report["outcome"] = "not_configured"
        write_report(output, report)
        return 0
    if not token:
        report["outcome"] = "missing_token"
        report["error"] = "GH_TOKEN or GITHUB_TOKEN is required"
        write_report(output, report)
        return 1

    report["attempted"] = True
    try:
        resolution_specs = resolution_label_specs()
        ensure_labels(args.github_api_url, repo, token, resolution_specs)
        issues = find_scope_issues(
            args.github_api_url.rstrip("/"),
            repo,
            token,
            report["scope_key"],
        )
        if not issues:
            report["outcome"] = "no_open_issue"
            write_report(output, report)
            return 0

        encoded_repo = parse.quote(repo, safe="/")
        comment = build_comment(record, args.github_repository, args.github_run_id, args.github_workflow)
        resolved_issues: list[dict[str, Any]] = []
        for issue in issues:
            issue_number = issue["number"]
            issue_labels = apply_resolution_labels(issue.get("labels"))
            _, comment_body = api_request(
                "POST",
                f"{args.github_api_url.rstrip('/')}/repos/{encoded_repo}/issues/{issue_number}/comments",
                token,
                {"body": comment},
            )
            api_request(
                "PATCH",
                f"{args.github_api_url.rstrip('/')}/repos/{encoded_repo}/issues/{issue_number}",
                token,
                {
                    "state": "closed",
                    "state_reason": "completed",
                    "labels": issue_labels,
                },
            )
            resolved_issues.append(
                {
                    "issue_number": issue_number,
                    "issue_url": issue.get("html_url"),
                    "comment_url": comment_body.get("html_url") if isinstance(comment_body, dict) else None,
                }
            )
        report["resolved"] = True
        report["outcome"] = "closed_open_issues"
        report["resolved_issues"] = resolved_issues
        report["resolved_labels"] = [spec["name"] for spec in resolution_specs]
    except Exception as exc:
        report["outcome"] = "resolution_error"
        report["error"] = str(exc)
        write_report(output, report)
        return 1

    write_report(output, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, parse, request

from incident_issue_labels import open_issue_label_names, open_issue_label_specs


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


def build_title(record: dict[str, Any]) -> str:
    context = record.get("record_context", {}) or {}
    return (
        f"[pqmsg {record.get('operation', 'incident')} incident] "
        f"{context.get('release_tag', 'unknown')} "
        f"{context.get('environment_name', 'unknown')}/"
        f"{context.get('deployment_mode', 'unknown')} "
        f"{context.get('release_name', 'unknown')}"
    )


def build_body(
    record: dict[str, Any],
    submission: dict[str, Any] | None,
    issue_key: str,
    scope_key: str,
    repository: str,
    run_id: str,
    workflow_name: str,
) -> str:
    context = record.get("record_context", {}) or {}
    failed = record.get("failed_checks") or []
    next_actions = record.get("next_actions") or []
    operation = record.get("operation", "unknown")
    deployment_mode = context.get("deployment_mode", "unknown")
    release_tag = context.get("release_tag", "unknown")
    bundle_name = f"{operation}-bundle-{release_tag}-{deployment_mode}"
    evidence_files = {
        "promote": [
            "promotion-record.json",
            "post-deploy-verification.json",
            "deployment-drift.json",
            "live-policy-verification.json",
            "live-routing-verification.json",
            "promotion-failure-handoff.json",
            "promotion-incident-submission.json",
        ],
        "rollback": [
            "rollback-record.json",
            "post-rollback-verification.json",
            "rollback-drift.json",
            "live-rollback-policy-verification.json",
            "live-rollback-routing-verification.json",
            "rollback-failure-handoff.json",
            "rollback-incident-submission.json",
        ],
    }.get(operation, [])
    lines = [
        f"<!-- pqmsg-incident-key: {issue_key} -->",
        f"<!-- pqmsg-incident-scope: {scope_key} -->",
        f"# {build_title(record)}",
        "",
        f"- Operation: `{record.get('operation', 'unknown')}`",
        f"- Release tag: `{context.get('release_tag', 'unknown')}`",
        f"- Environment: `{context.get('environment_name', 'unknown')}`",
        f"- Deployment mode: `{context.get('deployment_mode', 'unknown')}`",
        f"- Release name: `{context.get('release_name', 'unknown')}`",
        f"- Namespace: `{context.get('namespace', 'unknown')}`",
        f"- Target image: `{context.get('target_image', 'unknown')}`",
        f"- Job status: `{record.get('job_status', 'unknown')}`",
        f"- Failed check count: `{record.get('failed_check_count', 0)}`",
        f"- Suspicious drift count: `{record.get('suspicious_drift_count', 0)}`",
        f"- Workflow: `{workflow_name}`",
        f"- Workflow run: https://github.com/{repository}/actions/runs/{run_id}",
        f"- Evidence bundle artifact: `{bundle_name}`",
        "",
        "## Evidence Pointers",
        f"- Workflow run: https://github.com/{repository}/actions/runs/{run_id}",
        f"- Artifact bundle name: `{bundle_name}`",
    ]
    for item in evidence_files:
        lines.append(f"- Artifact file: `{item}`")
    lines.extend(
        [
            "",
        "## Failed Checks",
        ]
    )
    for item in failed[:10]:
        lines.append(f"- `{item.get('source', 'unknown')}:{item.get('name', 'unknown')}`")
    if not failed:
        lines.append("- none")
    if submission is not None:
        lines.extend(
            [
                "",
                "## Alertmanager Submission",
                f"- Outcome: `{submission.get('outcome')}`",
                f"- Attempted: `{submission.get('attempted')}`",
                f"- Delivered: `{submission.get('submitted')}`",
                f"- Status code: `{submission.get('status_code')}`",
            ]
        )
    if next_actions:
        lines.extend(["", "## Next Actions"])
        for item in next_actions:
            lines.append(f"- {item}")
    return "\n".join(lines) + "\n"


def find_existing_issue(
    api_url: str, repo: str, token: str, issue_key: str
) -> dict[str, Any] | None:
    encoded_repo = parse.quote(repo, safe="/")
    status, body = api_request(
        "GET",
        f"{api_url}/repos/{encoded_repo}/issues?state=open&per_page=100",
        token,
    )
    if status != 200 or not isinstance(body, list):
        return None
    marker = f"pqmsg-incident-key: {issue_key}"
    for item in body:
        if item.get("pull_request"):
            continue
        title = item.get("title", "")
        issue_body = item.get("body", "") or ""
        if marker in issue_body or title == issue_key:
            return item
    return None


def find_existing_comment(
    api_url: str,
    repo: str,
    token: str,
    issue_number: int,
    marker: str,
) -> dict[str, Any] | None:
    encoded_repo = parse.quote(repo, safe="/")
    status, body = api_request(
        "GET",
        f"{api_url.rstrip('/')}/repos/{encoded_repo}/issues/{issue_number}/comments?per_page=100",
        token,
    )
    if status != 200 or not isinstance(body, list):
        return None
    for item in body:
        if marker in str(item.get("body", "")):
            return item
    return None


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


def add_labels_to_issue(
    api_url: str,
    repo: str,
    token: str,
    issue_number: int,
    labels: list[str],
) -> None:
    encoded_repo = parse.quote(repo, safe="/")
    api_request(
        "POST",
        f"{api_url.rstrip('/')}/repos/{encoded_repo}/issues/{issue_number}/labels",
        token,
        {"labels": labels},
    )


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Publish incident to GitHub Issues")
    parser.add_argument("--failure-handoff", required=True)
    parser.add_argument("--submission-record")
    parser.add_argument("--repo", default="")
    parser.add_argument("--github-api-url", required=True)
    parser.add_argument("--github-repository", required=True)
    parser.add_argument("--github-run-id", required=True)
    parser.add_argument("--github-workflow", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    record = load_json(Path(args.failure_handoff))
    submission = load_json(Path(args.submission_record)) if args.submission_record and Path(args.submission_record).is_file() else None
    repo = args.repo.strip()
    token_value = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""

    report = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "incident_required": bool(record.get("incident_required")),
        "repo": repo,
        "attempted": False,
        "published": False,
        "outcome": "unknown",
        "issue_number": None,
        "issue_url": None,
        "comment_url": None,
        "labels": [],
        "error": None,
    }

    output = Path(args.output)
    if not report["incident_required"]:
        report["outcome"] = "not_required"
        write_report(output, report)
        return 0
    if not repo:
        report["outcome"] = "not_configured"
        write_report(output, report)
        return 0
    if not token_value:
        report["outcome"] = "missing_token"
        report["error"] = "GH_TOKEN or GITHUB_TOKEN is required"
        write_report(output, report)
        return 1

    issue_key = build_title(record)
    scope_key = build_scope_key(record)
    label_specs = open_issue_label_specs(record)
    label_names = open_issue_label_names(record)
    comment_marker = f"pqmsg-incident-comment:{args.github_workflow}|{args.github_run_id}|{issue_key}"
    body = build_body(
        record,
        submission,
        issue_key,
        scope_key,
        args.github_repository,
        args.github_run_id,
        args.github_workflow,
    )

    report["attempted"] = True
    try:
        ensure_labels(args.github_api_url, repo, token_value, label_specs)
        existing = find_existing_issue(args.github_api_url.rstrip("/"), repo, token_value, issue_key)
        encoded_repo = parse.quote(repo, safe="/")
        if existing is not None:
            issue_number = existing["number"]
            add_labels_to_issue(args.github_api_url, repo, token_value, issue_number, label_names)
            existing_comment = find_existing_comment(
                args.github_api_url,
                repo,
                token_value,
                issue_number,
                comment_marker,
            )
            if existing_comment is not None:
                report["published"] = True
                report["outcome"] = "existing_comment_already_present"
                report["issue_number"] = issue_number
                report["issue_url"] = existing.get("html_url")
                report["scope_key"] = scope_key
                report["labels"] = label_names
                report["comment_url"] = existing_comment.get("html_url")
                write_report(output, report)
                return 0
            _, comment_body = api_request(
                "POST",
                f"{args.github_api_url.rstrip('/')}/repos/{encoded_repo}/issues/{issue_number}/comments",
                token_value,
                {"body": f"<!-- {comment_marker} -->\n{body}"},
            )
            report["published"] = True
            report["outcome"] = "commented_existing_issue"
            report["issue_number"] = issue_number
            report["issue_url"] = existing.get("html_url")
            report["scope_key"] = scope_key
            report["labels"] = label_names
            if isinstance(comment_body, dict):
                report["comment_url"] = comment_body.get("html_url")
        else:
            _, issue_body = api_request(
                "POST",
                f"{args.github_api_url.rstrip('/')}/repos/{encoded_repo}/issues",
                token_value,
                {"title": issue_key, "body": body, "labels": label_names},
            )
            report["published"] = True
            report["outcome"] = "created_issue"
            report["scope_key"] = scope_key
            report["labels"] = label_names
            if isinstance(issue_body, dict):
                report["issue_number"] = issue_body.get("number")
                report["issue_url"] = issue_body.get("html_url")
    except Exception as exc:
        report["outcome"] = "publication_error"
        report["error"] = str(exc)
        write_report(output, report)
        return 1

    write_report(output, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

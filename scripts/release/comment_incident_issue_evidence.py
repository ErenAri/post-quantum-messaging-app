#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, parse, request


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def build_comment(
    manifest: dict[str, Any],
    manifest_path: Path,
    manifest_sha256: str,
    repository: str,
    run_id: str,
    workflow_name: str,
) -> str:
    bundle_kind = str(manifest.get("bundle_kind", "unknown"))
    release_tag = str(manifest.get("release_tag", "unknown"))
    deployment_mode = str(manifest.get("deployment_mode", "unknown"))
    bundle_name = f"{bundle_kind}-bundle-{release_tag}-{deployment_mode}"
    marker = f"pqmsg-incident-evidence:{bundle_kind}|{release_tag}|{deployment_mode}|{run_id}|{manifest_sha256}"
    return "\n".join(
        [
            f"<!-- {marker} -->",
            "Recorded final evidence bundle manifest for this workflow.",
            "",
            f"- Workflow: `{workflow_name}`",
            f"- Workflow run: https://github.com/{repository}/actions/runs/{run_id}",
            f"- Evidence bundle artifact: `{bundle_name}`",
            f"- Bundle manifest file: `{manifest_path.name}`",
            f"- Bundle manifest sha256: `{manifest_sha256}`",
            f"- Evidence file count: `{manifest.get('file_count', 0)}`",
        ]
    ) + "\n"


def collect_issue_numbers(issue_record: dict[str, Any]) -> list[int]:
    issue_number = issue_record.get("issue_number")
    if isinstance(issue_number, int):
        return [issue_number]
    issues: list[int] = []
    for item in issue_record.get("resolved_issues") or []:
        value = item.get("issue_number")
        if isinstance(value, int):
            issues.append(value)
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Comment final bundle-manifest evidence onto incident issues")
    parser.add_argument("--issue-record", required=True)
    parser.add_argument("--bundle-manifest", required=True)
    parser.add_argument("--repo", default="")
    parser.add_argument("--github-api-url", required=True)
    parser.add_argument("--github-repository", required=True)
    parser.add_argument("--github-run-id", required=True)
    parser.add_argument("--github-workflow", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    issue_record = load_json(Path(args.issue_record))
    repo = args.repo.strip()
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    output = Path(args.output)

    report = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo": repo,
        "attempted": False,
        "commented": False,
        "outcome": "unknown",
        "manifest_sha256": None,
        "bundle_manifest": None,
        "issue_numbers": [],
        "comment_urls": [],
        "error": None,
    }

    if not repo:
        report["outcome"] = "not_configured"
        write_report(output, report)
        return 0
    if not token:
        report["outcome"] = "missing_token"
        report["error"] = "GH_TOKEN or GITHUB_TOKEN is required"
        write_report(output, report)
        return 1

    manifest_path = Path(args.bundle_manifest)
    if not manifest_path.is_file():
        report["outcome"] = "manifest_missing"
        report["error"] = f"missing bundle manifest: {manifest_path}"
        write_report(output, report)
        return 1

    issue_numbers = collect_issue_numbers(issue_record)
    if not issue_numbers:
        report["outcome"] = "no_issue"
        write_report(output, report)
        return 0

    manifest = load_json(manifest_path)
    manifest_sha = sha256(manifest_path)
    bundle_kind = str(manifest.get("bundle_kind", "unknown"))
    release_tag = str(manifest.get("release_tag", "unknown"))
    deployment_mode = str(manifest.get("deployment_mode", "unknown"))
    marker = f"pqmsg-incident-evidence:{bundle_kind}|{release_tag}|{deployment_mode}|{args.github_run_id}|{manifest_sha}"
    body = build_comment(
        manifest,
        manifest_path,
        manifest_sha,
        args.github_repository,
        args.github_run_id,
        args.github_workflow,
    )

    report["attempted"] = True
    report["manifest_sha256"] = manifest_sha
    report["bundle_manifest"] = manifest_path.name
    encoded_repo = parse.quote(repo, safe="/")
    existing_count = 0
    new_count = 0
    try:
        for issue_number in issue_numbers:
            existing = find_existing_comment(
                args.github_api_url,
                repo,
                token,
                issue_number,
                marker,
            )
            if existing is not None:
                report["issue_numbers"].append(issue_number)
                report["comment_urls"].append(existing.get("html_url"))
                existing_count += 1
                continue
            _, comment_body = api_request(
                "POST",
                f"{args.github_api_url.rstrip('/')}/repos/{encoded_repo}/issues/{issue_number}/comments",
                token,
                {"body": body},
            )
            report["issue_numbers"].append(issue_number)
            if isinstance(comment_body, dict):
                report["comment_urls"].append(comment_body.get("html_url"))
            new_count += 1
        report["commented"] = new_count > 0
        report["outcome"] = "commented_issue_evidence" if new_count > 0 else "existing_comment_already_present"
    except Exception as exc:
        report["outcome"] = "comment_error"
        report["error"] = str(exc)
        write_report(output, report)
        return 1

    write_report(output, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

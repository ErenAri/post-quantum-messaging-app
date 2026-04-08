#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
RELEASE_TAG_PATTERN = re.compile(r"^v[0-9A-Za-z][0-9A-Za-z._-]*$")


def run(command: list[str], *, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if check and result.returncode != 0:
        raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"command failed: {' '.join(command)}")
    return result


def git_output(repo_root: Path, *args: str) -> str:
    result = run(["git", *args], cwd=repo_root)
    return result.stdout.strip()


def validate_release_tag(tag: str) -> None:
    if not RELEASE_TAG_PATTERN.match(tag):
        raise SystemExit(
            f"invalid release tag '{tag}'. Tagged release workflow requires tags that start with 'v'."
        )


def load_candidate_report(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"candidate readiness report not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON in candidate readiness report {path}: {exc}") from exc
    if payload.get("phase") != "candidate":
        raise SystemExit(f"candidate readiness report must have phase='candidate': {path}")
    checks = payload.get("checks")
    if not isinstance(checks, list) or not checks:
        raise SystemExit(f"candidate readiness report has no checks: {path}")
    bad_checks = [str(item.get("name", "unknown")) for item in checks if item.get("status") != "ok"]
    if bad_checks:
        raise SystemExit("candidate readiness report contains failing checks: " + ", ".join(bad_checks))
    return payload


def ensure_clean_worktree(repo_root: Path) -> None:
    status = git_output(repo_root, "status", "--porcelain")
    if status:
        raise SystemExit("git worktree is not clean; commit or stash changes before creating a pilot release tag")


def ensure_tag_absent(repo_root: Path, tag: str) -> None:
    local = run(["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"], cwd=repo_root, check=False)
    if local.returncode == 0:
        raise SystemExit(f"git tag already exists locally: {tag}")


def create_tag(repo_root: Path, tag: str, message: str) -> None:
    run(["git", "tag", "-a", tag, "-m", message], cwd=repo_root)


def push_tag(repo_root: Path, remote: str, tag: str) -> None:
    run(["git", "push", remote, f"refs/tags/{tag}"], cwd=repo_root)


def write_output(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fail-closed preparation for a pilot release candidate tag after the candidate gate is green."
    )
    parser.add_argument("--tag", required=True, help="Release tag to create, for example v0.1.0-rc1.")
    parser.add_argument(
        "--candidate-readiness",
        type=Path,
        default=REPO_ROOT / "dist" / "pilot-candidate-readiness.json",
        help="Path to the green candidate readiness report.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Git repository root to validate and tag.",
    )
    parser.add_argument("--create-tag", action="store_true", help="Create the annotated release tag after validation.")
    parser.add_argument("--push", action="store_true", help="Push the created tag to the remote after creation.")
    parser.add_argument("--remote", default="origin", help="Git remote used when --push is set.")
    parser.add_argument("--message", help="Annotated tag message. Defaults to 'Pilot release candidate <tag>'.")
    parser.add_argument("--output", type=Path, help="Optional JSON output path.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    validate_release_tag(args.tag)
    repo_root = args.repo_root.resolve()
    load_candidate_report(args.candidate_readiness.resolve())
    ensure_clean_worktree(repo_root)
    ensure_tag_absent(repo_root, args.tag)

    head_sha = git_output(repo_root, "rev-parse", "HEAD")
    branch = git_output(repo_root, "rev-parse", "--abbrev-ref", "HEAD")

    created_tag = False
    pushed_tag = False
    tag_message = args.message or f"Pilot release candidate {args.tag}"

    if args.push and not args.create_tag:
        raise SystemExit("--push requires --create-tag")

    if args.create_tag:
        create_tag(repo_root, args.tag, tag_message)
        created_tag = True
        if args.push:
            push_tag(repo_root, args.remote, args.tag)
            pushed_tag = True

    payload = {
        "repo_root": str(repo_root),
        "tag": args.tag,
        "head_sha": head_sha,
        "branch": branch,
        "candidate_readiness": str(args.candidate_readiness.resolve()),
        "created_tag": created_tag,
        "pushed_tag": pushed_tag,
        "remote": args.remote if args.push else None,
    }
    if args.output:
        write_output(args.output, payload)

    print(f"Pilot release tag: {args.tag}")
    print(f"HEAD: {head_sha}")
    print(f"Branch: {branch}")
    print(f"Created tag: {'yes' if created_tag else 'no'}")
    print(f"Pushed tag: {'yes' if pushed_tag else 'no'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RECOMMENDED_VARS = {
    "PQMSG_POSTGRES_STORAGE_ENCRYPTION": "managed_service",
    "PQMSG_POSTGRES_BACKUP_ENCRYPTION": "true",
    "PQMSG_AUDIT_LOG_PATH": "/var/log/pqmsg/audit.jsonl",
}
REQUIRED_SECRETS = (
    "KUBECONFIG_B64",
    "PQMSG_DATABASE_URL",
    "PQMSG_RATE_LIMIT_REDIS_URL",
    "PQMSG_SENDER_CERT_SIGNING_KEY",
)
OPTIONAL_SECRETS = (
    "PQMSG_SENTRY_DSN",
    "PQMSG_FCM_SERVER_KEY",
    "PQMSG_APNS_BEARER_TOKEN",
    "PQMSG_APNS_TOPIC",
    "PQMSG_ALERTMANAGER_API_URL",
)
REQUIRED_VARS = (
    "PQMSG_POSTGRES_STORAGE_ENCRYPTION",
    "PQMSG_POSTGRES_BACKUP_ENCRYPTION",
    "PQMSG_CORS_ALLOWED_ORIGINS",
    "PQMSG_AUDIT_LOG_PATH",
)
OPTIONAL_VARS = (
    "PQMSG_SENTRY_TRACES_SAMPLE_RATE",
    "PQMSG_AUDIT_LOG_MAX_BYTES",
    "PQMSG_AUDIT_LOG_MAX_FILES",
    "PQMSG_INCIDENT_ISSUE_REPO",
)


def run_command(command: list[str], *, cwd: Path = REPO_ROOT, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"command failed: {' '.join(command)}")
    return result


def gh_json(repo: str, args: list[str]) -> Any:
    result = run_command(["gh", *args, "--repo", repo], check=False)
    if result.returncode != 0:
        raise SystemExit(result.stderr.strip() or result.stdout.strip())
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"failed to parse JSON from gh {' '.join(args)}: {exc}") from exc


def gh_run(repo: str, args: list[str]) -> None:
    run_command(["gh", *args, "--repo", repo], check=True)


def infer_repo() -> str:
    result = run_command(["gh", "repo", "view", "--json", "nameWithOwner"], check=False)
    if result.returncode != 0:
        raise SystemExit("unable to determine repository; pass --repo OWNER/REPO")
    payload = json.loads(result.stdout)
    return str(payload["nameWithOwner"])


def parse_assignment(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise SystemExit(f"expected KEY=VALUE, got: {value}")
    name, rhs = value.split("=", 1)
    if not name or not rhs:
        raise SystemExit(f"expected non-empty KEY=VALUE, got: {value}")
    return name, rhs


def auth_check() -> None:
    result = run_command(["gh", "auth", "status"], check=False)
    if result.returncode != 0:
        raise SystemExit("gh auth status failed; authenticate gh before bootstrapping the pilot environment")


def get_environment(repo: str, environment_name: str) -> dict[str, Any] | None:
    result = run_command(["gh", "api", f"repos/{repo}/environments/{environment_name}"], check=False)
    if result.returncode != 0:
        stderr = result.stderr or ""
        if "404" in stderr or "Not Found" in stderr:
            return None
        raise SystemExit(stderr.strip() or result.stdout.strip())
    return json.loads(result.stdout)


def create_environment(repo: str, environment_name: str) -> dict[str, Any]:
    result = run_command(
        ["gh", "api", "--method", "PUT", f"repos/{repo}/environments/{environment_name}"],
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(result.stderr.strip() or result.stdout.strip())
    return json.loads(result.stdout)


def list_names(repo: str, command: list[str]) -> list[str]:
    payload = gh_json(repo, command)
    return sorted(str(item["name"]) for item in payload)


def set_environment_inputs(
    repo: str,
    environment_name: str,
    vars_inline: list[tuple[str, str]],
    vars_from_env: list[tuple[str, str]],
    secrets_from_env: list[tuple[str, str]],
) -> None:
    for name, value in vars_inline:
        gh_run(repo, ["variable", "set", name, "--env", environment_name, "--body", value])
    for name, env_name in vars_from_env:
        value = os.environ.get(env_name)
        if value is None:
            raise SystemExit(f"local environment variable not set: {env_name}")
        gh_run(repo, ["variable", "set", name, "--env", environment_name, "--body", value])
    for name, env_name in secrets_from_env:
        value = os.environ.get(env_name)
        if value is None:
            raise SystemExit(f"local environment variable not set: {env_name}")
        gh_run(repo, ["secret", "set", name, "--env", environment_name, "--body", value])


def write_output(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create/check the GitHub Actions environment used for the Android pilot.")
    parser.add_argument("--repo", help="GitHub repo in OWNER/REPO form. Defaults to the current gh repo.")
    parser.add_argument("--environment-name", default="pilot", help="GitHub Environment to check or create.")
    parser.add_argument("--create", action="store_true", help="Create the environment if it does not already exist.")
    parser.add_argument(
        "--set-var",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Set an environment variable in the target GitHub Environment.",
    )
    parser.add_argument(
        "--set-var-from-env",
        action="append",
        default=[],
        metavar="KEY=LOCAL_ENV",
        help="Set a GitHub Environment variable from a local environment variable.",
    )
    parser.add_argument(
        "--set-secret-from-env",
        action="append",
        default=[],
        metavar="KEY=LOCAL_ENV",
        help="Set a GitHub Environment secret from a local environment variable.",
    )
    parser.add_argument("--output", type=Path, help="Optional JSON output path.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    auth_check()

    repo = args.repo or infer_repo()
    environment_name = args.environment_name

    environment = get_environment(repo, environment_name)
    created = False
    if environment is None:
        if not args.create:
            raise SystemExit(
                f"GitHub Environment '{environment_name}' does not exist in {repo}. "
                "Rerun with --create to bootstrap it."
            )
        environment = create_environment(repo, environment_name)
        created = True

    vars_inline = [parse_assignment(item) for item in args.set_var]
    vars_from_env = [parse_assignment(item) for item in args.set_var_from_env]
    secrets_from_env = [parse_assignment(item) for item in args.set_secret_from_env]
    if vars_inline or vars_from_env or secrets_from_env:
        set_environment_inputs(repo, environment_name, vars_inline, vars_from_env, secrets_from_env)

    configured_secrets = list_names(repo, ["secret", "list", "--env", environment_name, "--json", "name"])
    configured_vars = list_names(repo, ["variable", "list", "--env", environment_name, "--json", "name"])

    missing_required_secrets = sorted(name for name in REQUIRED_SECRETS if name not in configured_secrets)
    missing_required_vars = sorted(name for name in REQUIRED_VARS if name not in configured_vars)
    missing_optional_secrets = sorted(name for name in OPTIONAL_SECRETS if name not in configured_secrets)
    missing_optional_vars = sorted(name for name in OPTIONAL_VARS if name not in configured_vars)

    payload = {
        "repo": repo,
        "environment_name": environment_name,
        "environment_exists": True,
        "created_environment": created,
        "environment_url": environment.get("html_url"),
        "required_secrets": list(REQUIRED_SECRETS),
        "required_vars": list(REQUIRED_VARS),
        "optional_secrets": list(OPTIONAL_SECRETS),
        "optional_vars": list(OPTIONAL_VARS),
        "configured_secrets": configured_secrets,
        "configured_vars": configured_vars,
        "missing_required_secrets": missing_required_secrets,
        "missing_required_vars": missing_required_vars,
        "missing_optional_secrets": missing_optional_secrets,
        "missing_optional_vars": missing_optional_vars,
        "recommended_defaults": DEFAULT_RECOMMENDED_VARS,
        "notes": {
            "PQMSG_CORS_ALLOWED_ORIGINS": "set this explicitly to the pilot HTTPS origin; wildcard origins are forbidden",
            "push_credentials": "FCM/APNs credentials are optional for the pilot gate but recommended if push delivery is in scope",
        },
        "ready_for_promotion": not missing_required_secrets and not missing_required_vars,
    }

    if args.output:
        write_output(args.output, payload)

    print(f"GitHub Environment: {environment_name}")
    print(f"Repository: {repo}")
    print(f"Created this run: {'yes' if created else 'no'}")
    print(f"Configured required secrets: {len(REQUIRED_SECRETS) - len(missing_required_secrets)}/{len(REQUIRED_SECRETS)}")
    print(f"Configured required vars: {len(REQUIRED_VARS) - len(missing_required_vars)}/{len(REQUIRED_VARS)}")
    if missing_required_secrets:
        print("Missing required secrets: " + ", ".join(missing_required_secrets))
    if missing_required_vars:
        print("Missing required vars: " + ", ".join(missing_required_vars))
    print(f"Ready for promotion: {'yes' if payload['ready_for_promotion'] else 'no'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"missing required environment variable: {name}")
    return value


def optional_env(name: str) -> str:
    return os.environ.get(name, "").strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render hardened Helm values from environment variables for release promotion."
    )
    parser.add_argument("--output", required=True, help="Output YAML/JSON file path")
    parser.add_argument(
        "--deployment-mode",
        choices=["pilot", "production"],
        required=True,
        help="Hardened deployment mode for the promoted release",
    )
    args = parser.parse_args()

    postgres_storage = required_env("PQMSG_POSTGRES_STORAGE_ENCRYPTION")
    postgres_backup = required_env("PQMSG_POSTGRES_BACKUP_ENCRYPTION").lower()
    if postgres_backup != "true":
        raise SystemExit("PQMSG_POSTGRES_BACKUP_ENCRYPTION must be true for hardened promotion")
    audit_log_path = required_env("PQMSG_AUDIT_LOG_PATH")

    payload: dict[str, dict[str, str]] = {
        "env": {
            "PQMSG_DEPLOYMENT_MODE": args.deployment_mode,
            "PQMSG_LOG_FORMAT": "json",
            "PQMSG_POSTGRES_STORAGE_ENCRYPTION": postgres_storage,
            "PQMSG_POSTGRES_BACKUP_ENCRYPTION": "true",
            "PQMSG_AUDIT_LOG_PATH": audit_log_path,
        },
        "secretEnv": {
            "PQMSG_DATABASE_URL": required_env("PQMSG_DATABASE_URL"),
            "PQMSG_RATE_LIMIT_REDIS_URL": required_env("PQMSG_RATE_LIMIT_REDIS_URL"),
            "PQMSG_SENDER_CERT_SIGNING_KEY": required_env("PQMSG_SENDER_CERT_SIGNING_KEY"),
        },
    }

    cors_origins = optional_env("PQMSG_CORS_ALLOWED_ORIGINS")
    if cors_origins:
        payload["env"]["PQMSG_CORS_ALLOWED_ORIGINS"] = cors_origins

    sentry_traces = optional_env("PQMSG_SENTRY_TRACES_SAMPLE_RATE")
    if sentry_traces:
        payload["env"]["PQMSG_SENTRY_TRACES_SAMPLE_RATE"] = sentry_traces

    for name in ("PQMSG_AUDIT_LOG_MAX_BYTES", "PQMSG_AUDIT_LOG_MAX_FILES"):
        value = optional_env(name)
        if value:
            payload["env"][name] = value

    if args.deployment_mode == "production":
        payload["secretEnv"]["PQMSG_SENTRY_DSN"] = required_env("PQMSG_SENTRY_DSN")
    else:
        sentry_dsn = optional_env("PQMSG_SENTRY_DSN")
        if sentry_dsn:
            payload["secretEnv"]["PQMSG_SENTRY_DSN"] = sentry_dsn

    for name in ("PQMSG_FCM_SERVER_KEY", "PQMSG_APNS_BEARER_TOKEN", "PQMSG_APNS_TOPIC"):
        value = optional_env(name)
        if value:
            payload["secretEnv"][name] = value

    output = Path(args.output)
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

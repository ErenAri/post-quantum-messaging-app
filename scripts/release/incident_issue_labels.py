#!/usr/bin/env python3
from __future__ import annotations

import re
from typing import Any


def _slugify(value: Any, default: str = "unknown") -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    if not text:
        text = default
    return text[:32]


def _truncate_description(text: str) -> str:
    return text[:100]


def open_issue_label_specs(record: dict[str, Any]) -> list[dict[str, str]]:
    context = record.get("record_context", {}) or {}
    environment = str(context.get("environment_name", "unknown"))
    deployment_mode = str(context.get("deployment_mode", "unknown"))
    operation = str(record.get("operation", "unknown"))

    environment_slug = _slugify(environment)
    deployment_mode_slug = _slugify(deployment_mode)
    operation_slug = _slugify(operation)

    return [
        {
            "name": "pqmsg-incident",
            "color": "b60205",
            "description": "Automated pqmsg incident record.",
        },
        {
            "name": "pqmsg-governance",
            "color": "5319e7",
            "description": "Release governance evidence or failure tracking.",
        },
        {
            "name": "pqmsg-severity-critical",
            "color": "d73a4a",
            "description": "Critical governance incident requiring operator action.",
        },
        {
            "name": "pqmsg-status-open",
            "color": "fbca04",
            "description": "Incident is active or unresolved.",
        },
        {
            "name": f"pqmsg-operation-{operation_slug}",
            "color": "1d76db",
            "description": _truncate_description(f"Incident originated during the {operation} workflow."),
        },
        {
            "name": f"pqmsg-env-{environment_slug}",
            "color": "0e8a16",
            "description": _truncate_description(f"Incident scoped to the {environment} environment."),
        },
        {
            "name": f"pqmsg-mode-{deployment_mode_slug}",
            "color": "6f42c1",
            "description": _truncate_description(f"Incident scoped to the {deployment_mode} deployment mode."),
        },
    ]


def resolution_label_specs() -> list[dict[str, str]]:
    return [
        {
            "name": "pqmsg-status-resolved",
            "color": "0e8a16",
            "description": "Incident has been remediated and closed.",
        }
    ]


def open_issue_label_names(record: dict[str, Any]) -> list[str]:
    return [spec["name"] for spec in open_issue_label_specs(record)]


def apply_resolution_labels(existing_labels: list[Any] | None) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for item in existing_labels or []:
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
        else:
            name = str(item).strip()
        if not name or name == "pqmsg-status-open" or name in seen:
            continue
        names.append(name)
        seen.add(name)
    if "pqmsg-status-resolved" not in seen:
        names.append("pqmsg-status-resolved")
    return names

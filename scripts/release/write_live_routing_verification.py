#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path


def split_yaml_documents(text: str) -> list[str]:
    docs: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        if line.strip() == "---":
            if any(part.strip() for part in current):
                docs.append("\n".join(current).strip() + "\n")
            current = []
            continue
        current.append(line)
    if any(part.strip() for part in current):
        docs.append("\n".join(current).strip() + "\n")
    return docs


def find_doc_by_kind(text: str, kind: str) -> str | None:
    for doc in split_yaml_documents(text):
        if re.search(rf"(?m)^kind:\s*{re.escape(kind)}\s*$", doc):
            return doc
    return None


def extract_indented_block(text: str, key: str, parent_indent: int) -> str | None:
    child_indent = parent_indent + 2
    pattern = re.compile(
        rf"(?ms)^[ ]{{{parent_indent}}}{re.escape(key)}:\s*\n"
        rf"(?P<block>(?:^[ ]{{{child_indent},}}.*(?:\n|$)|^[ ]{{{parent_indent}}}-.*(?:\n|$))*)"
    )
    match = pattern.search(text)
    if match is None:
        return None
    block = match.group("block")
    return block if block.strip() else None


def extract_line_value(block: str | None, pattern: str) -> str | None:
    if not block:
        return None
    match = re.search(pattern, block, re.MULTILINE)
    if match is None:
        return None
    return match.group(1).strip().strip('"')


def extract_service_contract(doc: str) -> dict[str, str | int | None]:
    metadata = extract_indented_block(doc, "metadata", 0)
    spec = extract_indented_block(doc, "spec", 0)
    selector = extract_indented_block(spec or "", "selector", 2)
    ports = extract_indented_block(spec or "", "ports", 2)
    return {
        "name": extract_line_value(metadata, r"^  name:\s*(\S+)\s*$"),
        "type": extract_line_value(spec, r"^  type:\s*(\S+)\s*$"),
        "selector_name": extract_line_value(
            selector, r"^    app\.kubernetes\.io/name:\s*(\S+)\s*$"
        ),
        "selector_instance": extract_line_value(
            selector, r"^    app\.kubernetes\.io/instance:\s*(\S+)\s*$"
        ),
        "port_name": extract_line_value(ports, r"^\s*-\s*name:\s*(\S+)\s*$"),
        "port": extract_line_value(ports, r"^\s*port:\s*(\S+)\s*$"),
        "target_port": extract_line_value(ports, r"^\s*targetPort:\s*(\S+)\s*$"),
    }


def extract_ingress_contract(doc: str) -> dict[str, str | None]:
    metadata = extract_indented_block(doc, "metadata", 0)
    spec = extract_indented_block(doc, "spec", 0)
    tls = extract_indented_block(spec or "", "tls", 2)
    rules = extract_indented_block(spec or "", "rules", 2)

    ingress_class = extract_line_value(spec, r"^  ingressClassName:\s*(\S+)\s*$")
    host = extract_line_value(rules, r"^\s+- host:\s*(\S+)\s*$")
    path_type = extract_line_value(rules, r"^\s+pathType:\s*(\S+)\s*$")
    backend_service_name = extract_line_value(rules, r"^\s+name:\s*(\S+)\s*$")
    backend_service_port = extract_line_value(rules, r"^\s+number:\s*(\S+)\s*$")
    tls_secret_name = extract_line_value(tls, r"^\s+secretName:\s*(\S+)\s*$")

    return {
        "name": extract_line_value(metadata, r"^  name:\s*(\S+)\s*$"),
        "ingress_class_name": ingress_class,
        "host": host,
        "path_type": path_type,
        "backend_service_name": backend_service_name,
        "backend_service_port": backend_service_port,
        "tls_secret_name": tls_secret_name,
    }


def compare_contracts(
    prefix: str, expected: dict[str, str | int | None], live: dict[str, str | int | None]
) -> list[str]:
    failures: list[str] = []
    for key, expected_value in expected.items():
        if expected_value in (None, ""):
            continue
        live_value = live.get(key)
        if live_value != expected_value:
            failures.append(
                f"{prefix}.{key} mismatch: expected {expected_value!r}, observed {live_value!r}"
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify live Service/Ingress routing contract")
    parser.add_argument("--rendered-chart", required=True)
    parser.add_argument("--service-manifest", required=True)
    parser.add_argument("--ingress-manifest", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    rendered_chart_text = Path(args.rendered_chart).read_text(encoding="utf-8")
    live_service_text = Path(args.service_manifest).read_text(encoding="utf-8")
    live_ingress_text = Path(args.ingress_manifest).read_text(encoding="utf-8")

    expected_service_doc = find_doc_by_kind(rendered_chart_text, "Service")
    expected_ingress_doc = find_doc_by_kind(rendered_chart_text, "Ingress")

    live_service_doc = live_service_text if live_service_text.strip() else None
    live_ingress_doc = live_ingress_text if live_ingress_text.strip() else None

    if expected_service_doc is None:
        raise SystemExit("rendered chart is missing Service manifest")
    if live_service_doc is None:
        raise SystemExit("live service manifest is empty")

    service_failures: list[str] = []
    if not re.search(r"(?m)^kind:\s*Service\s*$", live_service_doc):
        service_failures.append("live service manifest is not kind Service")
    expected_service = extract_service_contract(expected_service_doc)
    live_service = extract_service_contract(live_service_doc)
    service_failures.extend(compare_contracts("service", expected_service, live_service))

    ingress_failures: list[str] = []
    ingress_expected = expected_ingress_doc is not None
    ingress_present = live_ingress_doc is not None
    expected_ingress: dict[str, str | None] | None = None
    live_ingress: dict[str, str | None] | None = None

    if ingress_expected and not ingress_present:
        ingress_failures.append("live ingress resource is missing")
    elif not ingress_expected and ingress_present:
        ingress_failures.append("unexpected live ingress resource is present")
    elif ingress_expected and ingress_present:
        if not re.search(r"(?m)^kind:\s*Ingress\s*$", live_ingress_doc):
            ingress_failures.append("live ingress manifest is not kind Ingress")
        expected_ingress = extract_ingress_contract(expected_ingress_doc)
        live_ingress = extract_ingress_contract(live_ingress_doc)
        ingress_failures.extend(compare_contracts("ingress", expected_ingress, live_ingress))

    report = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "passed": not (service_failures or ingress_failures),
        "rendered_chart": args.rendered_chart,
        "service_manifest": args.service_manifest,
        "ingress_manifest": args.ingress_manifest,
        "service_name": live_service.get("name"),
        "ingress_expected": ingress_expected,
        "ingress_present": ingress_present,
        "checks": [
            {
                "name": "live_service_routing_contract",
                "passed": not service_failures,
                "failures": service_failures,
                "expected": expected_service,
                "observed": live_service,
            },
            {
                "name": "live_ingress_routing_contract",
                "passed": not ingress_failures,
                "skipped": not ingress_expected and not ingress_present,
                "failures": ingress_failures,
                "expected": expected_ingress,
                "observed": live_ingress,
            },
        ],
    }

    Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

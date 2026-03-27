#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def load_registry(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build_report(payload: dict) -> str:
    findings = payload.get("findings", [])
    severity_counts = Counter(
        entry["severity"] for entry in findings if isinstance(entry, dict) and "severity" in entry
    )
    status_counts = Counter(
        entry["status"] for entry in findings if isinstance(entry, dict) and "status" in entry
    )

    lines = [
        "# Audit Findings Summary",
        "",
        "- Registry: `docs/AUDIT_FINDINGS.json`",
        f"- Total findings: `{len(findings)}`",
        f"- Severity counts: `{dict(sorted(severity_counts.items()))}`",
        f"- Status counts: `{dict(sorted(status_counts.items()))}`",
        "",
    ]
    if findings:
        lines.extend(
            [
                "| Finding ID | Severity | Status | Component | Title |",
                "|------------|----------|--------|-----------|-------|",
            ]
        )
        for finding in findings:
            lines.append(
                "| {finding_id} | {severity} | {status} | {affected_component} | {title} |".format(
                    finding_id=finding["finding_id"],
                    severity=finding["severity"],
                    status=finding["status"],
                    affected_component=finding["affected_component"],
                    title=finding["title"],
                )
            )
    else:
        lines.append("No audit findings are currently tracked in the registry.")

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Render a Markdown summary of audit findings.")
    parser.add_argument(
        "--registry",
        default="docs/AUDIT_FINDINGS.json",
        help="Path to the audit findings registry",
    )
    parser.add_argument(
        "--output",
        help="Optional output Markdown path; prints to stdout when omitted",
    )
    args = parser.parse_args()

    report = build_report(load_registry(Path(args.registry)))
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report, encoding="utf-8")
    else:
        print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

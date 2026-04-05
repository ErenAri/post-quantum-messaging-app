#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


REPO_ROOT = Path(__file__).resolve().parents[2]
SUPPORT_MATRIX_PATH = REPO_ROOT / "docs" / "SUPPORT_MATRIX.json"
FUZZ_TARGETS = (
    "fuzz_tlv_decode",
    "fuzz_wire_decode",
    "fuzz_handshake_decode",
    "fuzz_sealed_decode",
    "fuzz_algorithm_dispatch",
)


@dataclass
class CheckResult:
    name: str
    command: str
    cwd: str
    status: str


def check(name: str, value: bool, details: dict[str, Any]) -> dict[str, Any]:
    return {"name": name, "passed": bool(value), "details": details}


def run_command(command: list[str], cwd: Path, extra_env: dict[str, str] | None = None) -> None:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(command, cwd=cwd, env=env)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def powershell_script(path: str, *args: str) -> list[str]:
    if os.name == "nt":
        return ["powershell", "-File", path, *args]
    script = path.replace(".ps1", ".sh")
    return ["bash", script, *args]


def candidate_checks() -> list[tuple[str, Path, list[str], dict[str, str] | None]]:
    return [
        ("Cargo fmt", REPO_ROOT, ["cargo", "fmt", "--all", "--check"], None),
        (
            "Cargo clippy",
            REPO_ROOT,
            ["cargo", "clippy", "--workspace", "--all-targets", "--features", "pqmsg-core/pq-rust", "--", "-D", "warnings"],
            None,
        ),
        (
            "Cargo test",
            REPO_ROOT,
            ["cargo", "test", "--workspace", "--all-targets", "--features", "pqmsg-core/pq-rust"],
            None,
        ),
        ("Cargo audit", REPO_ROOT, ["cargo", "audit"], None),
        ("Cargo deny", REPO_ROOT, ["cargo", "deny", "check", "advisories", "licenses", "bans", "sources"], None),
        (
            "Support matrix validator",
            REPO_ROOT,
            [sys.executable, "scripts/security/validate_support_matrix.py"],
            None,
        ),
        (
            "Audit findings validator",
            REPO_ROOT,
            [sys.executable, "scripts/security/validate_audit_findings.py"],
            None,
        ),
        (
            "Release audit gate validator",
            REPO_ROOT,
            [sys.executable, "scripts/security/validate_release_audit_gate.py"],
            None,
        ),
        (
            "Release governance workflow validator",
            REPO_ROOT,
            [sys.executable, "scripts/security/validate_release_governance_workflows.py"],
            None,
        ),
        (
            "Release governance helper smoke",
            REPO_ROOT,
            [sys.executable, "scripts/release/smoke_release_governance_helpers.py"],
            None,
        ),
        (
            "Supported client flows",
            REPO_ROOT,
            [sys.executable, "scripts/dev/validate_supported_client_flows.py", "--surface", "all"],
            {"CARGO_TARGET_DIR": str(REPO_ROOT / "target" / "pilot-android")},
        ),
    ]


def launch_checks(args: argparse.Namespace) -> list[tuple[str, Path, list[str], dict[str, str] | None]]:
    checks: list[tuple[str, Path, list[str], dict[str, str] | None]] = []
    for target in FUZZ_TARGETS:
        checks.append(
            (
                f"Parser fuzz smoke ({target})",
                REPO_ROOT / "crates" / "pqmsg-core",
                ["cargo", "+nightly", "fuzz", "run", target, "--", f"-max_total_time={args.fuzz_seconds}"],
                None,
            )
        )

    checks.extend(
        [
            (
                "ProVerif smoke",
                REPO_ROOT,
                powershell_script("scripts/security/run_proverif.ps1"),
                None,
            ),
            (
                "Penetration smoke",
                REPO_ROOT,
                powershell_script("scripts/security/pentest_smoke.ps1", "-Server", args.server),
                None,
            ),
            (
                "Alert escalation drill",
                REPO_ROOT,
                powershell_script(
                    "scripts/security/alert_drill.ps1",
                    "-Alertmanager",
                    args.alertmanager,
                    "-Mailpit",
                    args.mailpit,
                ),
                None,
            ),
        ]
    )
    return checks


def load_support_matrix() -> dict:
    return json.loads(SUPPORT_MATRIX_PATH.read_text(encoding="utf-8"))


def fetch_json(url: str) -> dict[str, Any]:
    try:
        with urlopen(url) as response:
            payload = response.read().decode("utf-8")
    except HTTPError as exc:
        raise SystemExit(f"{url} returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise SystemExit(f"failed to reach {url}: {exc.reason}") from exc

    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{url} did not return valid JSON") from exc


def validate_live_runtime_contract(server: str, support_matrix: dict[str, Any]) -> dict[str, Any]:
    current = support_matrix.get("current_beta_scope", {}) or {}
    health = fetch_json(f"{server.rstrip('/')}/health")
    capabilities = fetch_json(f"{server.rstrip('/')}/v1/capabilities")

    expected_support_subset = {
        "supported_beta_clients": current.get("supported_beta_clients"),
        "web_client_policy": current.get("web_client_policy"),
        "calling_supported": current.get("calling_supported"),
        "group_messaging_supported": current.get("group_messaging_supported"),
        "private_group_messaging_supported": current.get("private_group_messaging_supported"),
    }
    actual_support_subset = {
        key: capabilities.get(key) for key in expected_support_subset.keys()
    }

    checks = [
        check("health_status_ok", health.get("status") == "ok", {"status": health.get("status")}),
        check("health_db_ready", health.get("db_ready") is True, {"db_ready": health.get("db_ready")}),
        check("health_tls_enabled", health.get("tls_enabled") is True, {"tls_enabled": health.get("tls_enabled")}),
        check(
            "health_audit_logger_enabled",
            health.get("audit_logger_enabled") is True,
            {"audit_logger_enabled": health.get("audit_logger_enabled")},
        ),
        check(
            "health_production_baseline_met",
            health.get("production_baseline_met") is True,
            {"production_baseline_met": health.get("production_baseline_met")},
        ),
        check(
            "health_deployment_mode_match",
            health.get("deployment_mode") == "pilot",
            {"expected": "pilot", "actual": health.get("deployment_mode")},
        ),
        check(
            "health_security_profile_match",
            health.get("security_profile") == "high_assurance",
            {"expected": "high_assurance", "actual": health.get("security_profile")},
        ),
        check(
            "capabilities_tls_required",
            capabilities.get("tls_required") is True,
            {"tls_required": capabilities.get("tls_required")},
        ),
        check(
            "capabilities_tls_enabled",
            capabilities.get("tls_enabled") is True,
            {"tls_enabled": capabilities.get("tls_enabled")},
        ),
        check(
            "capabilities_production_baseline_met",
            capabilities.get("production_baseline_met") is True,
            {"production_baseline_met": capabilities.get("production_baseline_met")},
        ),
        check(
            "capabilities_deployment_mode_match",
            capabilities.get("deployment_mode") == "pilot",
            {"expected": "pilot", "actual": capabilities.get("deployment_mode")},
        ),
        check(
            "capabilities_security_profile_match",
            capabilities.get("security_profile") == "high_assurance",
            {"expected": "high_assurance", "actual": capabilities.get("security_profile")},
        ),
        check(
            "capabilities_sealed_sender_required",
            capabilities.get("sealed_sender_required") is True,
            {"sealed_sender_required": capabilities.get("sealed_sender_required")},
        ),
        check(
            "capabilities_authenticated_dm_disabled",
            capabilities.get("authenticated_direct_messaging_supported") is False,
            {
                "authenticated_direct_messaging_supported": capabilities.get(
                    "authenticated_direct_messaging_supported"
                )
            },
        ),
        check(
            "capabilities_sender_certificates_enabled",
            capabilities.get("sender_certificate_supported") is True,
            {"sender_certificate_supported": capabilities.get("sender_certificate_supported")},
        ),
        check(
            "capabilities_key_transparency_enabled",
            capabilities.get("key_transparency_supported") is True,
            {"key_transparency_supported": capabilities.get("key_transparency_supported")},
        ),
        check(
            "capabilities_support_boundary_match_docs",
            expected_support_subset == actual_support_subset,
            {"expected": expected_support_subset, "actual": actual_support_subset},
        ),
    ]

    failed = [item for item in checks if not item["passed"]]
    if failed:
        for item in failed:
            print(f"live runtime verification failed: {item['name']} -> {item['details']}", file=sys.stderr)
        raise SystemExit(1)

    return {
        "server": server,
        "health": health,
        "capabilities": capabilities,
        "checks": checks,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the candidate or launch gate for the Android messaging pilot."
    )
    parser.add_argument(
        "--phase",
        choices=("candidate", "launch"),
        default="candidate",
        help="Readiness phase to validate. Default: candidate.",
    )
    parser.add_argument(
        "--server",
        help="Pilot server base URL for the launch phase, for example https://pilot.example.com",
    )
    parser.add_argument(
        "--alertmanager",
        default="http://127.0.0.1:9093",
        help="Alertmanager base URL for the alert drill. Default: http://127.0.0.1:9093",
    )
    parser.add_argument(
        "--mailpit",
        default="http://127.0.0.1:8025",
        help="Mailpit base URL for drill delivery checks. Default: http://127.0.0.1:8025",
    )
    parser.add_argument(
        "--fuzz-seconds",
        type=int,
        default=20,
        help="Per-target parser fuzz duration in seconds for the launch phase. Default: 20.",
    )
    parser.add_argument(
        "--output",
        help="Optional path to write a JSON readiness report.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.phase == "launch" and not args.server:
        raise SystemExit("--server is required when --phase launch is used")

    matrix = load_support_matrix()
    current = matrix.get("current_beta_scope", {})

    print("Pilot readiness validation")
    print(f"- Phase: {args.phase}")
    print(f"- Support matrix summary: {current.get('summary', 'unknown')}")
    print(f"- Supported rollout clients: {current.get('supported_beta_clients', [])}")
    print(f"- Web client policy: {current.get('web_client_policy', 'unknown')}")

    live_runtime_report: dict[str, Any] | None = None
    if args.phase == "launch":
        print(f"[run] Live runtime contract: {args.server}")
        live_runtime_report = validate_live_runtime_contract(args.server, matrix)

    checks = candidate_checks()
    if args.phase == "launch":
        checks.extend(launch_checks(args))

    completed: list[CheckResult] = []
    for name, cwd, command, extra_env in checks:
        command_display = " ".join(command)
        print(f"[run] {name}: {command_display}")
        run_command(command, cwd, extra_env)
        completed.append(CheckResult(name=name, command=command_display, cwd=str(cwd), status="ok"))

    report = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "phase": args.phase,
        "support_matrix": current,
        "checks": [asdict(item) for item in completed],
    }
    if live_runtime_report is not None:
        report["live_runtime"] = live_runtime_report

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\nReadiness report written to {output_path}")

    print("\nPilot readiness validation complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SUPPORT_MATRIX_PATH = REPO_ROOT / "docs" / "SUPPORT_MATRIX.json"


@dataclass
class CheckResult:
    name: str
    command: str
    status: str


def run_command(command: list[str], cwd: Path) -> None:
    if os.name == "nt":
        result = subprocess.run(["cmd", "/c", *command], cwd=cwd)
    else:
        result = subprocess.run(command, cwd=cwd)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def load_support_matrix() -> dict:
    return json.loads(SUPPORT_MATRIX_PATH.read_text(encoding="utf-8"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the current supported/demo client flows before refreshing screenshots "
            "or shipping a new beta snapshot."
        )
    )
    parser.add_argument(
        "--surface",
        choices=("all", "web", "android"),
        default="all",
        help="Which client surface to validate. Default: all.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    matrix = load_support_matrix()
    current = matrix.get("current_beta_scope", {})
    supported_beta_clients = current.get("supported_beta_clients", [])
    web_client_policy = current.get("web_client_policy", "unknown")

    print("Supported-flow validation matrix")
    print(f"- Support matrix summary: {current.get('summary', 'unknown')}")
    print(f"- Supported beta clients: {supported_beta_clients}")
    print(f"- Web client policy: {web_client_policy}")

    checks: list[tuple[str, Path, list[str]]] = [
        (
            "Support-matrix contract",
            REPO_ROOT,
            [sys.executable, "scripts/security/validate_support_matrix.py"],
        ),
    ]

    if args.surface in ("all", "web"):
        checks.extend(
            [
                (
                    "Web demo/shell flow coverage",
                    REPO_ROOT / "mobile" / "web",
                    ["npm", "test", "--", "src/app.flow.test.ts"],
                ),
                (
                    "Web production build",
                    REPO_ROOT / "mobile" / "web",
                    ["npm", "run", "build"],
                ),
            ]
        )

    if args.surface in ("all", "android"):
        checks.append(
            (
                "Android beta messaging build/test",
                REPO_ROOT / "mobile" / "android",
                [".\\gradlew.bat", ":app:assembleDebug", "app:testDebugUnitTest"],
            )
        )

    completed: list[CheckResult] = []
    for name, cwd, command in checks:
        command_display = " ".join(command)
        print(f"[run] {name}: {command_display}")
        run_command(command, cwd)
        completed.append(CheckResult(name=name, command=command_display, status="ok"))

    print("\nValidation complete:")
    for item in completed:
        print(f"- {item.name}: {item.status}")

    if args.surface == "web":
        print("\nWeb screenshot capture may proceed.")
    elif args.surface == "android":
        print("\nAndroid screenshot refresh may proceed.")
    else:
        print("\nRelease screenshot refresh may proceed.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

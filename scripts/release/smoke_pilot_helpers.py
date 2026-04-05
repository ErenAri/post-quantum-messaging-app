#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
TMP = ROOT / "tmp_pilot_helper_smoke"


def run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=ROOT,
        check=check,
        text=True,
        capture_output=True,
    )


def load_json(path: pathlib.Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def make_dir(name: str) -> pathlib.Path:
    path = TMP / name
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json(path: pathlib.Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def candidate_payload() -> dict:
    return {
        "generated_at_utc": "2026-04-05T15:00:00Z",
        "phase": "candidate",
        "support_matrix": {"summary": "Android pilot for messaging only"},
        "checks": [{"name": "candidate_gate", "status": "ok"}],
    }


def launch_payload() -> dict:
    return {
        "generated_at_utc": "2026-04-05T15:10:00Z",
        "phase": "launch",
        "checks": [{"name": "launch_gate", "status": "ok"}],
        "live_runtime": {
            "server": "https://pilot.example.test",
            "checks": [
                {"name": "health_status_ok", "passed": True},
                {"name": "capabilities_support_boundary_match_docs", "passed": True},
            ],
        },
    }


def promotion_payload() -> dict:
    return {
        "generated_at_utc": "2026-04-05T15:15:00Z",
        "deployment_mode": "pilot",
        "apply_requested": True,
        "release_tag": "v0.1.0",
        "environment_name": "pilot",
        "namespace": "pqmsg-pilot",
        "release_name": "pqmsg-server",
    }


def manual_smoke_payload(step_status: str = "pass") -> dict:
    step_ids = [
        "provision_two_fresh_android_users",
        "direct_messages_both_directions",
        "private_group_create_and_message",
        "attachments_dm_and_private_group",
        "restart_and_inbox_sync_continuity",
        "trust_change_fail_closed_behavior",
        "stale_private_group_state_fail_closed_behavior",
    ]
    steps = []
    for index, step_id in enumerate(step_ids, start=20):
        steps.append(
            {
                "id": step_id,
                "description": step_id,
                "status": step_status,
                "tester": "QA",
                "completed_at_utc": f"2026-04-05T15:{index:02d}:00Z",
                "notes": "" if step_status == "pass" else "intentional failure path",
            }
        )
    return {"steps": steps}


def smoke_release_bundle_patterns() -> None:
    script = (ROOT / "scripts" / "release" / "download_release_bundle.sh").read_text(encoding="utf-8")
    required_patterns = [
        "pqmsg-server-linux-x86_64",
        "sbom.tar.gz",
        "release-manifest.json",
        "release-security-posture.json",
        "container-image.txt",
        "helm-image-overrides.yaml",
        "checksums.txt",
        "checksums.txt.sig",
        "checksums.txt.pem",
    ]
    for pattern in required_patterns:
        assert f'--pattern "{pattern}"' in script


def smoke_verify_release_bundle_checksum_paths() -> None:
    script = (ROOT / "scripts" / "release" / "verify_release_bundle.sh").read_text(encoding="utf-8")
    assert 'sha256sum --check < "$dist_dir/checksums.txt"' in script


def smoke_prepare_release_candidate() -> None:
    with tempfile.TemporaryDirectory(prefix="pqmsg-pilot-tag-") as raw_tmp:
        root = pathlib.Path(raw_tmp)
        repo = root / "repo"
        repo.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, text=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Pilot Smoke"], cwd=repo, check=True, text=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "pilot-smoke@example.test"], cwd=repo, check=True, text=True, capture_output=True)
        (repo / "README.md").write_text("pilot smoke\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=repo, check=True, text=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, text=True, capture_output=True)

        candidate_path = root / "candidate.json"
        output_path = root / "release.json"
        write_json(candidate_path, candidate_payload())

        subprocess.run(
            [
                "python",
                str(ROOT / "scripts" / "release" / "prepare_pilot_release_candidate.py"),
                "--repo-root",
                str(repo),
                "--candidate-readiness",
                str(candidate_path),
                "--tag",
                "v0.1.0-rc1",
                "--create-tag",
                "--output",
                str(output_path),
            ],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )

        report = load_json(output_path)
        assert isinstance(report, dict)
        assert report["created_tag"] is True
        tag_name = subprocess.run(
            ["git", "tag", "--list", "v0.1.0-rc1"],
            cwd=repo,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        assert tag_name == "v0.1.0-rc1"


def smoke_launch_handoff_success() -> None:
    path = make_dir("success")
    write_json(path / "candidate.json", candidate_payload())
    write_json(path / "launch.json", launch_payload())
    write_json(path / "promotion.json", promotion_payload())
    write_json(path / "manual.json", manual_smoke_payload("pass"))

    run(
        [
            "python",
            "scripts/release/write_pilot_launch_handoff.py",
            "--candidate-readiness",
            str(path / "candidate.json"),
            "--launch-readiness",
            str(path / "launch.json"),
            "--manual-smoke",
            str(path / "manual.json"),
            "--promotion-record",
            str(path / "promotion.json"),
            "--release-owner",
            "QA",
            "--rollback-owner",
            "OPS",
            "--output",
            str(path / "handoff.json"),
        ]
    )

    handoff = load_json(path / "handoff.json")
    assert isinstance(handoff, dict)
    assert handoff["ready_for_cohort_launch"] is True
    assert handoff["failed_requirements"] == []
    assert handoff["promotion_context"]["deployment_mode"] == "pilot"
    assert len(handoff["manual_smoke"]) == 7


def smoke_launch_handoff_fails_closed() -> None:
    path = make_dir("fail_closed")
    write_json(path / "candidate.json", candidate_payload())
    write_json(path / "launch.json", launch_payload())
    write_json(path / "manual.json", manual_smoke_payload("pending"))

    result = run(
        [
            "python",
            "scripts/release/write_pilot_launch_handoff.py",
            "--candidate-readiness",
            str(path / "candidate.json"),
            "--launch-readiness",
            str(path / "launch.json"),
            "--manual-smoke",
            str(path / "manual.json"),
            "--release-owner",
            "QA",
            "--rollback-owner",
            "OPS",
            "--output",
            str(path / "handoff.json"),
        ],
        check=False,
    )

    assert result.returncode == 1
    handoff = load_json(path / "handoff.json")
    assert isinstance(handoff, dict)
    assert handoff["ready_for_cohort_launch"] is False
    assert any(item.startswith("manual_smoke_pending_steps:") for item in handoff["failed_requirements"])


def main() -> int:
    shutil.rmtree(TMP, ignore_errors=True)
    TMP.mkdir(parents=True, exist_ok=True)
    try:
        smoke_release_bundle_patterns()
        smoke_verify_release_bundle_checksum_paths()
        smoke_prepare_release_candidate()
        smoke_launch_handoff_success()
        smoke_launch_handoff_fails_closed()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print("pilot helper smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

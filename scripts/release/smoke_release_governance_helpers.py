#!/usr/bin/env python3
from __future__ import annotations

import http.server
import json
import os
import pathlib
import shutil
import socketserver
import subprocess
import threading
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
TMP = ROOT / "tmp_release_governance_smoke"


def run(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        check=True,
        text=True,
        capture_output=True,
    )


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def make_dir(name: str) -> pathlib.Path:
    path = TMP / name
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


def smoke_failure_handoff_and_alert_payload() -> None:
    path = make_dir("handoff")
    (path / "record.json").write_text(
        json.dumps(
            {
                "release_tag": "v1.2.3",
                "namespace": "pqmsg",
                "release_name": "pqmsg-server",
                "environment_name": "prod",
                "deployment_mode": "production",
                "target_image": "ghcr.io/example/pqmsg-server@sha256:" + ("a" * 64),
            }
        ),
        encoding="utf-8",
    )
    (path / "runtime.json").write_text(
        json.dumps(
            {"passed": False, "checks": [{"name": "health_status_ok", "passed": False, "details": {"status": "degraded"}}]}
        ),
        encoding="utf-8",
    )
    (path / "routing.json").write_text(
        json.dumps(
            {
                "passed": False,
                "checks": [
                    {
                        "name": "live_service_routing_contract",
                        "passed": False,
                        "failures": ["service.port mismatch"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (path / "drift.json").write_text(
        json.dumps(
            {
                "suspicious_change_count": 1,
                "suspicious_changes": [{"resource": "tls_secret", "reason": "changed unexpectedly"}],
            }
        ),
        encoding="utf-8",
    )
    (path / "deployments.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "metadata": {"name": "pqmsg-server-pqmsg-server", "resourceVersion": "12", "generation": 2},
                        "status": {"observedGeneration": 1, "replicas": 2, "readyReplicas": 1, "availableReplicas": 1},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (path / "pods.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "metadata": {"name": "pqmsg-server-pod-1"},
                        "status": {
                            "phase": "Running",
                            "containerStatuses": [
                                {
                                    "name": "server",
                                    "ready": False,
                                    "restartCount": 2,
                                    "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                                }
                            ],
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (path / "pf.log").write_text("curl failed", encoding="utf-8")
    run(
        [
            "python",
            "scripts/release/write_failure_handoff_record.py",
            "--operation",
            "promote",
            "--job-status",
            "failure",
            "--record",
            str(path / "record.json"),
            "--runtime-verification",
            str(path / "runtime.json"),
            "--routing-verification",
            str(path / "routing.json"),
            "--drift-report",
            str(path / "drift.json"),
            "--deployments",
            str(path / "deployments.json"),
            "--pods",
            str(path / "pods.json"),
            "--port-forward-log",
            str(path / "pf.log"),
            "--output",
            str(path / "handoff.json"),
        ]
    )
    handoff = load_json(path / "handoff.json")
    assert handoff["incident_required"] is True
    run(
        [
            "python",
            "scripts/release/write_incident_alert_payload.py",
            "--failure-handoff",
            str(path / "handoff.json"),
            "--output-json",
            str(path / "alert.json"),
            "--output-md",
            str(path / "alert.md"),
        ]
    )
    payload = load_json(path / "alert.json")
    assert payload[0]["labels"]["severity"] == "critical"


def smoke_submit_incident_alert() -> None:
    path = make_dir("submit")
    (path / "handoff.json").write_text(json.dumps({"operation": "promote", "incident_required": True}), encoding="utf-8")
    (path / "payload.json").write_text("[]", encoding="utf-8")
    run(
        [
            "python",
            "scripts/release/submit_incident_alert.py",
            "--operation",
            "promote",
            "--failure-handoff",
            str(path / "handoff.json"),
            "--payload-json",
            str(path / "payload.json"),
            "--alertmanager-api-url",
            "",
            "--output",
            str(path / "skip.json"),
        ]
    )
    skip = load_json(path / "skip.json")
    assert skip["outcome"] == "not_configured"

    received: dict[str, Any] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8")
            received["path"] = self.path
            received["body"] = body
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        def log_message(self, *args):  # noqa: A003
            return

    srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        run(
            [
                "python",
                "scripts/release/submit_incident_alert.py",
                "--operation",
                "promote",
                "--failure-handoff",
                str(path / "handoff.json"),
                "--payload-json",
                str(path / "payload.json"),
                "--alertmanager-api-url",
                f"http://127.0.0.1:{port}",
                "--output",
                str(path / "ok.json"),
            ]
        )
    finally:
        srv.shutdown()
        thread.join()
    ok = load_json(path / "ok.json")
    assert ok["outcome"] == "submitted"
    assert ok["submitted"] is True
    assert received["path"] == "/api/v2/alerts"


def smoke_publish_and_resolve_incident_issue() -> None:
    path = make_dir("issues")
    (path / "handoff-open.json").write_text(
        json.dumps(
            {
                "operation": "promote",
                "incident_required": True,
                "record_context": {
                    "release_tag": "v1.2.3",
                    "environment_name": "prod",
                    "deployment_mode": "production",
                    "release_name": "pqmsg-server",
                    "namespace": "pqmsg",
                    "target_image": "img",
                },
                "failed_checks": [{"source": "runtime_contract", "name": "health_status_ok"}],
                "failed_check_count": 1,
                "suspicious_drift_count": 0,
                "next_actions": ["inspect"],
            }
        ),
        encoding="utf-8",
    )
    (path / "submission.json").write_text(
        json.dumps({"outcome": "submitted", "submitted": True, "attempted": True, "status_code": 200}),
        encoding="utf-8",
    )
    (path / "handoff-close.json").write_text(
        json.dumps(
            {
                "operation": "rollback",
                "incident_required": False,
                "record_context": {
                    "release_tag": "v1.2.4",
                    "environment_name": "prod",
                    "deployment_mode": "production",
                    "release_name": "pqmsg-server",
                    "namespace": "pqmsg",
                    "target_image": "img",
                },
            }
        ),
        encoding="utf-8",
    )
    received: dict[str, Any] = {
        "comments": [],
        "patches": [],
        "created_labels": [],
        "issue_label_posts": [],
        "evidence_comments": [],
        "publish_comments": [],
    }
    labels_by_name: dict[str, dict[str, Any]] = {}
    issue_comments: dict[int, list[dict[str, Any]]] = {7: [], 42: []}
    created_issue: dict[str, Any] | None = None
    scope_marker = "pqmsg-incident-scope: prod|production|pqmsg|pqmsg-server"

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path.startswith("/repos/owner/repo/labels/"):
                label_name = self.path.rsplit("/", 1)[-1]
                label_name = label_name.replace("%20", " ")
                from urllib.parse import unquote

                label_name = unquote(label_name)
                if label_name in labels_by_name:
                    body = json.dumps(labels_by_name[label_name])
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body.encode("utf-8"))
                    return
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"message":"Not Found"}')
                return
            if self.path.startswith("/repos/owner/repo/issues"):
                if self.path == "/repos/owner/repo/issues/42/comments?per_page=100":
                    body = json.dumps(issue_comments[42])
                elif self.path == "/repos/owner/repo/issues/7/comments?per_page=100":
                    body = json.dumps(issue_comments[7])
                else:
                    issues = [
                        {
                            "number": 7,
                            "html_url": "https://github.test/owner/repo/issues/7",
                            "body": f"<!-- {scope_marker} -->",
                            "labels": [{"name": "pqmsg-status-open"}, {"name": "pqmsg-incident"}],
                        }
                    ]
                    if created_issue is not None:
                        issues.append(created_issue)
                    body = json.dumps(issues)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body.encode("utf-8"))
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8")
            if self.path == "/repos/owner/repo/labels":
                payload = json.loads(body)
                labels_by_name[payload["name"]] = payload
                received["created_labels"].append(payload)
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(payload).encode("utf-8"))
                return
            if self.path == "/repos/owner/repo/issues":
                payload = json.loads(body)
                received["create"] = payload
                created_issue_dict = {
                    "number": 42,
                    "html_url": "https://github.test/owner/repo/issues/42",
                    "title": payload["title"],
                    "body": payload["body"],
                    "labels": [{"name": label} for label in payload.get("labels", [])],
                }
                nonlocal created_issue
                created_issue = created_issue_dict
                response = {"number": 42, "html_url": "https://github.test/owner/repo/issues/42"}
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response).encode("utf-8"))
                return
            if self.path in {"/repos/owner/repo/issues/7/labels", "/repos/owner/repo/issues/42/labels"}:
                received["issue_label_posts"].append(json.loads(body))
                response = [{"name": name} for name in json.loads(body).get("labels", [])]
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response).encode("utf-8"))
                return
            if self.path == "/repos/owner/repo/issues/42/comments":
                payload = json.loads(body)
                if "pqmsg-incident-comment:" in payload.get("body", ""):
                    received["publish_comments"].append({"issue": 42, "payload": payload})
                    response = {"html_url": "https://github.test/owner/repo/issues/42#issuecomment-publish"}
                else:
                    received["evidence_comments"].append({"issue": 42, "payload": payload})
                    response = {"html_url": "https://github.test/owner/repo/issues/42#issuecomment-2"}
                issue_comments[42].append({"body": payload["body"], "html_url": response["html_url"]})
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response).encode("utf-8"))
                return
            if self.path == "/repos/owner/repo/issues/7/comments":
                payload = json.loads(body)
                if "Resolved by successful" in payload.get("body", ""):
                    received["comments"].append(payload)
                    response = {"html_url": "https://github.test/owner/repo/issues/7#issuecomment-1"}
                else:
                    received["evidence_comments"].append({"issue": 7, "payload": payload})
                    response = {"html_url": "https://github.test/owner/repo/issues/7#issuecomment-3"}
                issue_comments[7].append({"body": payload["body"], "html_url": response["html_url"]})
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response).encode("utf-8"))
                return
            self.send_response(404)
            self.end_headers()

        def do_PATCH(self):  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8")
            if self.path in {"/repos/owner/repo/issues/7", "/repos/owner/repo/issues/42"}:
                received["patches"].append(json.loads(body))
                issue_number = 7 if self.path.endswith("/7") else 42
                response = {"number": issue_number, "html_url": f"https://github.test/owner/repo/issues/{issue_number}"}
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response).encode("utf-8"))
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args):  # noqa: A003
            return

    srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        env = dict(os.environ)
        env["GH_TOKEN"] = "test-token"
        run(
            [
                "python",
                "scripts/release/publish_incident_issue.py",
                "--failure-handoff",
                str(path / "handoff-open.json"),
                "--submission-record",
                str(path / "submission.json"),
                "--repo",
                "owner/repo",
                "--github-api-url",
                f"http://127.0.0.1:{port}",
                "--github-repository",
                "owner/repo",
                "--github-run-id",
                "123",
                "--github-workflow",
                "promote",
                "--output",
                str(path / "issue-open.json"),
            ],
            env=env,
        )
        run(
            [
                "python",
                "scripts/release/publish_incident_issue.py",
                "--failure-handoff",
                str(path / "handoff-open.json"),
                "--submission-record",
                str(path / "submission.json"),
                "--repo",
                "owner/repo",
                "--github-api-url",
                f"http://127.0.0.1:{port}",
                "--github-repository",
                "owner/repo",
                "--github-run-id",
                "123",
                "--github-workflow",
                "promote",
                "--output",
                str(path / "issue-open-rerun-1.json"),
            ],
            env=env,
        )
        run(
            [
                "python",
                "scripts/release/publish_incident_issue.py",
                "--failure-handoff",
                str(path / "handoff-open.json"),
                "--submission-record",
                str(path / "submission.json"),
                "--repo",
                "owner/repo",
                "--github-api-url",
                f"http://127.0.0.1:{port}",
                "--github-repository",
                "owner/repo",
                "--github-run-id",
                "123",
                "--github-workflow",
                "promote",
                "--output",
                str(path / "issue-open-rerun-2.json"),
            ],
            env=env,
        )
        run(
            [
                "python",
                "scripts/release/resolve_incident_issue.py",
                "--failure-handoff",
                str(path / "handoff-close.json"),
                "--repo",
                "owner/repo",
                "--github-api-url",
                f"http://127.0.0.1:{port}",
                "--github-repository",
                "owner/repo",
                "--github-run-id",
                "124",
                "--github-workflow",
                "rollback",
                "--output",
                str(path / "issue-close.json"),
            ],
            env=env,
        )
        dist = path / "dist"
        dist.mkdir(parents=True, exist_ok=True)
        (dist / "alpha.json").write_text('{"a":1}\n', encoding="utf-8")
        (dist / "beta.txt").write_text("beta\n", encoding="utf-8")
        run(
            [
                "python",
                "scripts/release/write_bundle_manifest.py",
                "--bundle-kind",
                "promotion",
                "--release-tag",
                "v1.2.3",
                "--deployment-mode",
                "production",
                "--dist-dir",
                str(dist),
                "--output",
                str(dist / "promotion-bundle-manifest.json"),
            ]
        )
        run(
            [
                "python",
                "scripts/release/comment_incident_issue_evidence.py",
                "--issue-record",
                str(path / "issue-open.json"),
                "--bundle-manifest",
                str(dist / "promotion-bundle-manifest.json"),
                "--repo",
                "owner/repo",
                "--github-api-url",
                f"http://127.0.0.1:{port}",
                "--github-repository",
                "owner/repo",
                "--github-run-id",
                "123",
                "--github-workflow",
                "promote",
                "--output",
                str(path / "issue-open-evidence.json"),
            ],
            env=env,
        )
        run(
            [
                "python",
                "scripts/release/comment_incident_issue_evidence.py",
                "--issue-record",
                str(path / "issue-close.json"),
                "--bundle-manifest",
                str(dist / "promotion-bundle-manifest.json"),
                "--repo",
                "owner/repo",
                "--github-api-url",
                f"http://127.0.0.1:{port}",
                "--github-repository",
                "owner/repo",
                "--github-run-id",
                "124",
                "--github-workflow",
                "rollback",
                "--output",
                str(path / "issue-close-evidence.json"),
            ],
            env=env,
        )
        run(
            [
                "python",
                "scripts/release/comment_incident_issue_evidence.py",
                "--issue-record",
                str(path / "issue-open.json"),
                "--bundle-manifest",
                str(dist / "promotion-bundle-manifest.json"),
                "--repo",
                "owner/repo",
                "--github-api-url",
                f"http://127.0.0.1:{port}",
                "--github-repository",
                "owner/repo",
                "--github-run-id",
                "123",
                "--github-workflow",
                "promote",
                "--output",
                str(path / "issue-open-evidence-rerun.json"),
            ],
            env=env,
        )
    finally:
        srv.shutdown()
        thread.join()

    issue_open = load_json(path / "issue-open.json")
    issue_open_rerun_1 = load_json(path / "issue-open-rerun-1.json")
    issue_open_rerun_2 = load_json(path / "issue-open-rerun-2.json")
    issue_close = load_json(path / "issue-close.json")
    issue_open_evidence = load_json(path / "issue-open-evidence.json")
    issue_open_evidence_rerun = load_json(path / "issue-open-evidence-rerun.json")
    issue_close_evidence = load_json(path / "issue-close-evidence.json")
    assert issue_open["outcome"] == "created_issue"
    assert issue_open["scope_key"] == "prod|production|pqmsg|pqmsg-server"
    assert "pqmsg-incident" in issue_open["labels"]
    assert "pqmsg-incident-scope: prod|production|pqmsg|pqmsg-server" in received["create"]["body"]
    assert "Evidence bundle artifact: `promote-bundle-v1.2.3-production`" in received["create"]["body"]
    assert "pqmsg-status-open" in received["create"]["labels"]
    assert any(item["name"] == "pqmsg-status-open" for item in received["created_labels"])
    assert any(item["name"] == "pqmsg-status-resolved" for item in received["created_labels"])
    assert issue_open_rerun_1["outcome"] == "commented_existing_issue"
    assert issue_open_rerun_2["outcome"] == "existing_comment_already_present"
    assert len(received["publish_comments"]) == 1
    assert issue_close["outcome"] == "closed_open_issues"
    assert issue_close["resolved"] is True
    assert received["patches"][0]["state"] == "closed"
    assert "pqmsg-status-resolved" in received["patches"][0]["labels"]
    assert "pqmsg-status-open" not in received["patches"][0]["labels"]
    assert "Evidence bundle artifact: `rollback-bundle-v1.2.4-production`" in received["comments"][0]["body"]
    assert issue_open_evidence["outcome"] == "commented_issue_evidence"
    assert issue_open_evidence_rerun["outcome"] == "existing_comment_already_present"
    assert issue_close_evidence["outcome"] == "commented_issue_evidence"
    assert issue_open_evidence["issue_numbers"] == [42]
    assert sorted(issue_close_evidence["issue_numbers"]) == [7, 42]
    assert any("Bundle manifest sha256:" in item["payload"]["body"] for item in received["evidence_comments"])
    assert any(
        "Evidence bundle artifact: `promotion-bundle-v1.2.3-production`" in item["payload"]["body"]
        for item in received["evidence_comments"]
    )


def smoke_bundle_manifest() -> None:
    path = make_dir("bundle_manifest")
    dist = path / "dist"
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "alpha.json").write_text('{"a":1}\n', encoding="utf-8")
    (dist / "beta.txt").write_text("beta\n", encoding="utf-8")
    run(
        [
            "python",
            "scripts/release/write_bundle_manifest.py",
            "--bundle-kind",
            "promotion",
            "--release-tag",
            "v1.2.3",
            "--deployment-mode",
            "production",
            "--dist-dir",
            str(dist),
            "--output",
            str(dist / "promotion-bundle-manifest.json"),
        ]
    )
    manifest = load_json(dist / "promotion-bundle-manifest.json")
    assert manifest["bundle_kind"] == "promotion"
    assert manifest["release_tag"] == "v1.2.3"
    assert manifest["deployment_mode"] == "production"
    assert manifest["file_count"] == 2
    assert [item["path"] for item in manifest["files"]] == ["alpha.json", "beta.txt"]
    run(
        [
            "python",
            "scripts/release/verify_workflow_bundle.py",
            "--bundle-kind",
            "promotion",
            "--dist-dir",
            str(dist),
        ]
    )


def main() -> int:
    shutil.rmtree(TMP, ignore_errors=True)
    TMP.mkdir(parents=True, exist_ok=True)
    try:
        smoke_failure_handoff_and_alert_payload()
        smoke_submit_incident_alert()
        smoke_publish_and_resolve_incident_issue()
        smoke_bundle_manifest()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print("release governance helper smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

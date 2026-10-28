from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

_EMPTY_REPORT: dict[str, Any] = {
    "schema_version": "1.0",
    "status": "UNKNOWN",
    "summary": {"safe": 0, "review": 1, "block": 0},
    "findings": [
        {
            "rule_id": "ACTION-001",
            "severity": "high",
            "decision": "review",
            "file": "unknown",
            "location": {"line": 1, "column": 1},
            "message": "Safegate action could not produce a valid scan report.",
            "recommendation": "Check the action inputs and rerun the scan.",
            "evidence": "Scan process returned no valid JSON report.",
            "confidence": 1.0,
        }
    ],
}


def _input(name: str, default: str = "") -> str:
    suffixes = dict.fromkeys((name.upper().replace("-", "_"), name.upper()))
    for suffix in suffixes:
        value = os.environ.get(f"INPUT_{suffix}", "")
        if value:
            return value
    return default


def _read_report(stdout: str) -> dict[str, Any]:
    try:
        report = json.loads(stdout)
    except (TypeError, json.JSONDecodeError):
        return dict(_EMPTY_REPORT)
    if not isinstance(report, dict) or report.get("status") not in {
        "SAFE",
        "REVIEW",
        "BLOCK",
        "UNKNOWN",
    }:
        return dict(_EMPTY_REPORT)
    if not isinstance(report.get("findings"), list) or (
        report.get("status") == "UNKNOWN" and not report["findings"]
    ):
        return dict(_EMPTY_REPORT)
    return report


def _write_outputs(report: dict[str, Any]) -> None:
    status = report.get("status", "UNKNOWN")
    findings = report.get("findings", [])
    compact_report = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with Path(output_path).open("a", encoding="utf-8") as output:
            output.write(f"status={status}\n")
            output.write(f"findings-count={len(findings)}\n")
            output.write(f"report={compact_report}\n")
        return
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))


def _pull_request_context() -> tuple[str, int, str] | None:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not repository or not event_path:
        return None
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(event, dict):
        return None
    pull_request = event.get("pull_request")
    if not isinstance(pull_request, dict):
        return None
    number = pull_request.get("number", event.get("number"))
    head = pull_request.get("head")
    sha = head.get("sha") if isinstance(head, dict) else None
    if not isinstance(number, int) or not isinstance(sha, str) or not sha:
        return None
    return repository, number, sha


def run_action() -> int:
    files = _input("files", "**/*.sql")
    fail_on = _input("fail-on", "block")
    pg_version = _input("pg-version", "16")
    config = _input("config")
    command = [
        sys.executable,
        "-m",
        "safegate",
        "scan",
        files,
        "--format",
        "json",
        "--pg-version",
        pg_version,
        "--fail-on",
        fail_on,
    ]
    if config:
        command.extend(["--config", config])

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
        report = _read_report(completed.stdout)
        scan_exit_code = (
            2 if report.get("status") == "UNKNOWN" else completed.returncode
        )
    except (OSError, UnicodeError):
        report = dict(_EMPTY_REPORT)
        scan_exit_code = 2

    _write_outputs(report)

    token = _input("github-token") or os.environ.get("GITHUB_TOKEN", "")
    if token and os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
        context = _pull_request_context()
        if context is not None:
            repository, issue_number, head_sha = context
            try:
                from safegate.github.client import GitHubApiError
                from safegate.github.comment import publish_report

                publish_report(
                    report,
                    token=token,
                    repository=repository,
                    issue_number=issue_number,
                    head_sha=head_sha,
                    scan_exit_code=scan_exit_code,
                )
            except GitHubApiError:
                print(
                    "Safegate: GitHub reporting failed; scan result is unchanged.",
                    file=sys.stderr,
                )
    return scan_exit_code


def main() -> None:
    raise SystemExit(run_action())

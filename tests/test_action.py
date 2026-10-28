from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from safegate.github.client import GitHubApiError
from safegate.report import build_report


def _serialized_report(scan_sql_fixture) -> str:
    result = scan_sql_fixture("safe/clean.sql")
    return build_report([result]).model_dump_json()


def test_local_action_writes_json_outputs_and_preserves_scan_exit(
    monkeypatch, tmp_path: Path, scan_sql_fixture
) -> None:
    output = tmp_path / "github-output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("INPUT_FILES", "tests/fixtures/safe/clean.sql")
    monkeypatch.setenv("INPUT_FAIL_ON", "review")
    monkeypatch.setenv("INPUT_PG_VERSION", "16")
    monkeypatch.setenv("INPUT_CONFIG", "/tmp/safegate-policy.toml")
    monkeypatch.delenv("INPUT_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    stdout = _serialized_report(scan_sql_fixture)
    completed = subprocess.CompletedProcess(args=[], returncode=1, stdout=stdout)

    with (
        patch("safegate.github.action.subprocess.run", return_value=completed) as run,
        patch("urllib.request.urlopen") as open_url,
    ):
        from safegate.github.action import run_action

        result = run_action()

    assert result == 1
    assert run.call_args.args[0][:4] == [
        run.call_args.args[0][0],
        "-m",
        "safegate",
        "scan",
    ]
    assert "--fail-on" in run.call_args.args[0]
    assert run.call_args.args[0][-2:] == ["--config", "/tmp/safegate-policy.toml"]
    open_url.assert_not_called()
    values = output.read_text(encoding="utf-8")
    assert "status=SAFE" in values
    assert "findings-count=0" in values
    assert json.loads(values.split("report=", maxsplit=1)[1])["status"] == "SAFE"


def test_pull_request_timeout_keeps_scan_exit_code_and_report(
    monkeypatch, tmp_path: Path, scan_sql_fixture
) -> None:
    output = tmp_path / "github-output.txt"
    event_file = tmp_path / "event.json"
    event_file.write_text(
        json.dumps(
            {
                "number": 7,
                "pull_request": {"number": 7, "head": {"sha": "abc123"}},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_file))
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("INPUT_GITHUB_TOKEN", "token-value")
    stdout = _serialized_report(scan_sql_fixture)
    completed = subprocess.CompletedProcess(args=[], returncode=1, stdout=stdout)

    with (
        patch("safegate.github.action.subprocess.run", return_value=completed),
        patch(
            "safegate.github.comment.publish_report",
            side_effect=GitHubApiError("network timeout"),
        ),
    ):
        from safegate.github.action import run_action

        result = run_action()

    assert result == 1
    contents = output.read_text(encoding="utf-8")
    assert "status=SAFE" in contents
    assert "private API detail" not in contents


def test_invalid_scan_json_becomes_unknown_and_exit_two(
    fixture_path, monkeypatch, tmp_path: Path
) -> None:
    output = tmp_path / "github-output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("INPUT_FILES", str(fixture_path("safe/clean.sql")))
    monkeypatch.delenv("INPUT_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="not json")

    with patch("safegate.github.action.subprocess.run", return_value=completed):
        from safegate.github.action import run_action

        result = run_action()

    assert result == 2
    output_report = json.loads(
        output.read_text(encoding="utf-8").split("report=", maxsplit=1)[1]
    )
    assert output_report["status"] == "UNKNOWN"
    assert output_report["findings"][0]["rule_id"] == "ACTION-001"


def test_static_scan_does_not_import_github_http_client(
    fixture_path,
) -> None:
    scan_file = fixture_path("safe/clean.sql")
    code = (
        "import sys; from pathlib import Path; "
        "from safegate.config import SafegateConfig; "
        "from safegate.scan import scan_file; "
        f"scan_file(Path({str(scan_file)!r}), display_file='fixture.sql', "
        "config=SafegateConfig()); "
        "assert 'safegate.github.client' not in sys.modules"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr

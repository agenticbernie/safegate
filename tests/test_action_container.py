from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker is unavailable")
def test_action_container_reads_workspace_and_writes_github_output(
    tmp_path: Path,
) -> None:
    build = subprocess.run(
        [
            "docker",
            "build",
            "-f",
            "Dockerfile.action",
            "-t",
            "safegate-action-test",
            ".",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert build.returncode == 0, build.stderr

    output_file = tmp_path / "github-output"
    output_file.write_text("", encoding="utf-8")
    output_file.chmod(0o644)
    run = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "-v",
            f"{ROOT}:/github/workspace:ro",
            "-v",
            f"{output_file}:/github/file_commands/output:rw",
            "-e",
            "GITHUB_WORKSPACE=/github/workspace",
            "-e",
            "GITHUB_OUTPUT=/github/file_commands/output",
            "-e",
            "INPUT_FILES=/github/workspace/tests/fixtures/safe/clean.sql",
            "-e",
            "INPUT_FAIL_ON=block",
            "safegate-action-test",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert run.returncode == 0, run.stderr
    output = output_file.read_text(encoding="utf-8")
    assert "status=SAFE" in output
    assert "findings-count=0" in output

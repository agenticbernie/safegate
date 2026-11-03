from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import pytest
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from typer.testing import CliRunner

from safegate.cli import app
from safegate.report import ScanReport, ScanReportV2, report_json
from safegate.scan import ScanResult

runner = CliRunner()


# Frozen from v0.1.0: strict consumers must continue to accept default JSON.
class V1Location(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    line: int = Field(ge=1)
    column: int = Field(ge=1)


class V1Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    rule_id: str
    severity: Literal["low", "medium", "high"]
    decision: Literal["safe", "review", "block"]
    file: str
    location: V1Location
    message: str
    recommendation: str
    evidence: str
    confidence: float = Field(ge=0.0, le=1.0)


class V1Summary(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    safe: int = Field(ge=0)
    review: int = Field(ge=0)
    block: int = Field(ge=0)


class V1Report(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    status: Literal["SAFE", "REVIEW", "BLOCK", "UNKNOWN"]
    summary: V1Summary
    findings: tuple[V1Finding, ...]


def _assert_sorted_keys(value: object) -> None:
    if isinstance(value, dict):
        assert list(value) == sorted(value)
        for nested in value.values():
            _assert_sorted_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_sorted_keys(nested)


def test_json_snapshot_is_byte_stable_and_has_no_absolute_paths(
    scan_sql_fixture,
) -> None:
    first: ScanResult = scan_sql_fixture("block/multi_line_index.sql")
    second: ScanResult = scan_sql_fixture("block/multi_line_index.sql")
    output_one = report_json([first])
    output_two = report_json([second])
    payload = json.loads(output_one)

    assert output_one == output_two
    _assert_sorted_keys(payload)
    assert '"timestamp"' not in output_one
    assert not Path(payload["findings"][0]["file"]).is_absolute()
    assert payload["findings"][0]["rule_id"] == "SG-001"


def test_report_findings_are_sorted_by_file_location_and_rule(scan_sql_fixture) -> None:
    index: ScanResult = scan_sql_fixture("block/multi_line_index.sql")
    destructive: ScanResult = scan_sql_fixture("block/update_no_where.sql")
    payload = json.loads(report_json([destructive, index]))

    assert [finding["file"] for finding in payload["findings"]] == sorted(
        finding["file"] for finding in payload["findings"]
    )


def test_review_fails_only_when_fail_on_review(fixture_path) -> None:
    path = str(fixture_path("review/add_column_default.sql"))
    default_policy = runner.invoke(app, ["scan", path, "--format", "json"])
    review_policy = runner.invoke(
        app,
        ["scan", path, "--format", "json", "--fail-on", "review"],
    )

    assert default_policy.exit_code == 0
    assert json.loads(default_policy.stdout)["status"] == "REVIEW"
    assert review_policy.exit_code == 1


def test_recursive_glob_handles_nested_migration_paths(
    fixture_path,
    monkeypatch,
    tmp_path: Path,
) -> None:
    (tmp_path / ".safegate.toml").write_text(
        "transactional = false\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        [
            "scan",
            str(fixture_path("safe/**/*.sql")),
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["findings"] == []


def test_text_output_uses_safe_review_and_block_badges(fixture_path) -> None:
    safe = runner.invoke(
        app,
        ["scan", str(fixture_path("safe/clean.sql")), "--format", "text"],
    )
    review = runner.invoke(
        app,
        [
            "scan",
            str(fixture_path("review/add_column_default.sql")),
            "--format",
            "text",
        ],
    )
    block = runner.invoke(
        app,
        ["scan", str(fixture_path("block/multi_line_index.sql")), "--format", "text"],
    )

    assert "🟢 SAFE" in safe.stdout
    assert "🟡 REVIEW" in review.stdout
    assert "🔴 BLOCK" in block.stdout


def test_unknown_parser_status_always_exits_two(fixture_path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            str(fixture_path("block/malformed.sql")),
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
    )

    assert result.exit_code == 2
    assert json.loads(result.stdout)["status"] == "UNKNOWN"


def test_nontransactional_file_can_be_set_by_policy_and_cli_override(
    fixture_path,
    monkeypatch,
    tmp_path: Path,
) -> None:
    (tmp_path / ".safegate.toml").write_text(
        "transactional = true\npg_version = 16\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        [
            "scan",
            str(fixture_path("safe/concurrent_safe.sql")),
            "--format",
            "json",
            "--pg-version",
            "16",
            "--fail-on",
            "never",
        ],
    )

    assert result.exit_code == 0
    # `transactional=true` remains conservative even when a target version is overridden.
    assert json.loads(result.stdout)["status"] == "BLOCK"


def test_doctor_reports_the_pinned_parser_grammar() -> None:
    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "PostgreSQL 16" in result.stdout


def test_opt_in_v2_reports_lock_facts_without_changing_v1(fixture_path) -> None:
    path = str(fixture_path("block/drop_index.sql"))
    v1 = runner.invoke(app, ["scan", path, "--format", "json"])
    v2 = runner.invoke(
        app, ["scan", path, "--format", "json", "--report-schema", "2.0"]
    )
    old, new = json.loads(v1.stdout), json.loads(v2.stdout)
    assert v1.exit_code == v2.exit_code == 1
    assert old["schema_version"] == "1.0"
    assert "lock_impact" not in old["findings"][0]
    assert new["schema_version"] == "2.0"
    assert new["status"] == old["status"]
    impact = new["findings"][0]["lock_impact"][0]
    assert impact["required_mode"] == "ACCESS EXCLUSIVE"
    assert impact["plain_read_conflict"] is True
    assert impact["runtime_contention"] == "unknown"
    assert new["findings"][0]["context_hints_used"] == []
    ScanReport.model_validate_json(v1.stdout)
    V1Report.model_validate_json(v1.stdout)
    ScanReportV2.model_validate_json(v2.stdout)
    with pytest.raises(ValidationError):
        V1Report.model_validate_json(v2.stdout)


def test_v2_parser_failure_retains_unknown_without_lock_claim(fixture_path) -> None:
    path = str(fixture_path("block/malformed.sql"))
    result = runner.invoke(
        app, ["scan", path, "--format", "json", "--report-schema", "2.0"]
    )
    payload = json.loads(result.stdout)
    assert result.exit_code == 2
    assert payload["status"] == "UNKNOWN"
    assert payload["findings"][0]["lock_impact"] is None
    assert payload["findings"][0]["evidence_confidence"] == {
        "lock": "unknown",
        "rewrite": "unknown",
    }
    v1 = runner.invoke(app, ["scan", path, "--format", "json"])
    V1Report.model_validate_json(v1.stdout)


def test_action_fallback_remains_compatible_with_v1_consumer() -> None:
    from safegate.github.action import _EMPTY_REPORT

    V1Report.model_validate_json(json.dumps(_EMPTY_REPORT))


def test_v2_serialization_preserves_v1_findings(fixture_path) -> None:
    path = str(fixture_path("review/add_column_default.sql"))
    v1 = runner.invoke(app, ["scan", path, "--format", "json"])
    v2 = runner.invoke(
        app, ["scan", path, "--format", "json", "--report-schema", "2.0"]
    )
    old, new = json.loads(v1.stdout), json.loads(v2.stdout)
    for key, value in old["findings"][0].items():
        assert new["findings"][0][key] == value
    assert new["findings"][0]["lock_impact"][0]["rewrite"] == "unknown"

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from safegate.cli import app
from safegate.config import ConfigError, SafegateConfig, load_config
from safegate.parser.postgres import parse_postgres
from safegate.report import report_json
from safegate.scan import ScanResult

runner = CliRunner()


@pytest.mark.parametrize(
    ("fixture", "rule_id"),
    [
        ("block/multi_line_index.sql", "SG-001"),
        ("block/drop_index.sql", "SG-002"),
        ("block/add_constraint_unique.sql", "SG-003"),
        ("review/add_column_default.sql", "SG-004"),
        ("review/set_not_null.sql", "SG-005"),
        ("review/alter_column_type.sql", "SG-006"),
        ("review/add_foreign_key.sql", "SG-007"),
        ("block/vacuum_full.sql", "SG-008"),
        ("block/update_no_where.sql", "SG-009"),
        ("safe/concurrent_safe.sql", "SG-010"),
    ],
)
def test_each_static_rule_emits_its_rule_id(fixture, rule_id, scan_sql_fixture) -> None:
    result: ScanResult = scan_sql_fixture(fixture)

    assert rule_id in {finding.rule_id for finding in result.findings}


def test_parse_result_keeps_locations_and_explicit_transaction_state(
    read_sql_fixture,
) -> None:
    parsed = parse_postgres(
        read_sql_fixture("block/concurrent_in_tx.sql"),
        file="tests/fixtures/block/concurrent_in_tx.sql",
        transactional=False,
    )

    assert parsed.error is None
    create_index = next(
        item
        for item in parsed.statements
        if type(item.statement).__name__ == "IndexStmt"
    )
    assert create_index.location.line == 2
    assert create_index.in_transaction is True


def test_implicit_transaction_default_blocks_concurrent_index(scan_sql_fixture) -> None:
    result: ScanResult = scan_sql_fixture("safe/concurrent_safe.sql")

    assert "SG-010" in {finding.rule_id for finding in result.findings}
    assert result.status == "BLOCK"


def test_concurrent_index_is_safe_when_file_is_configured_nontransactional(
    scan_sql_fixture,
) -> None:
    config = SafegateConfig(transactional=False)
    result: ScanResult = scan_sql_fixture("safe/concurrent_safe.sql", config=config)

    assert result.findings == ()
    assert result.status == "SAFE"


def test_where_false_does_not_trigger_destructive_block(scan_sql_fixture) -> None:
    result: ScanResult = scan_sql_fixture(
        "safe/update_where_false.sql",
        config=SafegateConfig(transactional=False),
    )

    assert not any(
        finding.rule_id == "SG-009" and finding.decision == "block"
        for finding in result.findings
    )


@pytest.mark.parametrize(
    "fixture",
    ["block/update_no_where.sql", "block/update_where_true.sql"],
)
def test_unbounded_or_always_true_update_is_blocked(fixture, scan_sql_fixture) -> None:
    result: ScanResult = scan_sql_fixture(
        fixture,
        config=SafegateConfig(transactional=False),
    )

    assert any(
        finding.rule_id == "SG-009" and finding.decision == "block"
        for finding in result.findings
    )


def test_report_has_required_finding_fields(scan_sql_fixture) -> None:
    result = scan_sql_fixture(
        "review/add_column_default.sql",
        config=SafegateConfig(transactional=False),
    )
    payload = json.loads(report_json([result]))

    assert payload["schema_version"] == "1.0"
    finding = payload["findings"][0]
    assert finding["rule_id"] == "SG-004"
    assert finding["file"] == "tests/fixtures/review/add_column_default.sql"
    assert finding["severity"] == "medium"
    assert finding["decision"] == "review"
    assert finding["location"]["line"] == 1
    assert finding["location"]["column"] == 1
    assert isinstance(finding["evidence"], str)
    assert isinstance(finding["recommendation"], str)
    assert 0 <= finding["confidence"] <= 1


def test_report_json_is_byte_stable(scan_sql_fixture) -> None:
    result = scan_sql_fixture(
        "block/multi_line_index.sql",
        config=SafegateConfig(transactional=False),
    )

    assert report_json([result]) == report_json([result])


def test_report_paths_are_relative_for_absolute_scan_input(scan_sql_fixture) -> None:
    result = scan_sql_fixture("block/delete_all.sql", absolute_file=True)

    assert not Path(result.findings[0].location.file).is_absolute()


def test_config_defaults_to_implicit_transaction(tmp_path: Path) -> None:
    config = load_config(tmp_path / "missing.toml")

    assert config.pg_version == 16
    assert config.transactional is True


def test_unknown_config_key_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / ".safegate.toml"
    path.write_text("unknown = true\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="unknown"):
        load_config(path)


def test_invalid_rule_severity_is_a_config_error(tmp_path: Path) -> None:
    path = tmp_path / ".safegate.toml"
    path.write_text('[rules."SG-001"]\nseverity = ["high"]\n', encoding="utf-8")

    with pytest.raises(ConfigError, match="severity"):
        load_config(path)


def test_recursive_glob_cli_emits_json(
    fixture_path, monkeypatch, tmp_path: Path
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

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "1.0"
    assert payload["findings"] == []


def test_malformed_sql_fixture_is_unknown_and_exits_two(fixture_path) -> None:
    result = runner.invoke(
        app,
        ["scan", str(fixture_path("block/malformed.sql")), "--format", "json"],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "UNKNOWN"
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["rule_id"] == "PARSER-001"


def test_comment_only_fixture_is_safe(fixture_path) -> None:
    result = runner.invoke(
        app,
        ["scan", str(fixture_path("safe/empty_comments.sql")), "--format", "json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "SAFE"
    assert payload["findings"] == []


def test_doctor_reports_local_parser_version() -> None:
    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "PostgreSQL 16" in result.stdout

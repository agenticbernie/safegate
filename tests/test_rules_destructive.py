from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from safegate.cli import app
from safegate.scan import ScanResult

runner = CliRunner()


def _run(path: Path) -> tuple[int, dict[str, object]]:
    result = runner.invoke(app, ["scan", str(path), "--format", "json"])
    return result.exit_code, json.loads(result.stdout)


def test_update_where_false_is_not_blocked(fixture_path) -> None:
    code, payload = _run(fixture_path("safe/update_where_false.sql"))

    assert code == 0
    assert payload["status"] == "SAFE"
    assert all(finding["rule_id"] != "SG-009" for finding in payload["findings"])


def test_update_without_where_is_sg009_block(fixture_path) -> None:
    code, payload = _run(fixture_path("block/update_no_where.sql"))

    assert code == 1
    assert payload["status"] == "BLOCK"
    assert [finding["rule_id"] for finding in payload["findings"]] == ["SG-009"]


def test_update_with_always_true_where_is_sg009_block(fixture_path) -> None:
    code, payload = _run(fixture_path("block/update_where_true.sql"))

    assert code == 1
    assert payload["status"] == "BLOCK"
    assert [finding["rule_id"] for finding in payload["findings"]] == ["SG-009"]


def test_drop_table_is_sg009_block(scan_sql_fixture) -> None:
    result: ScanResult = scan_sql_fixture("block/drop_table.sql")

    assert result.status == "BLOCK"
    assert [finding.rule_id for finding in result.findings] == ["SG-009"]


def test_drop_column_is_sg009_block(scan_sql_fixture) -> None:
    result: ScanResult = scan_sql_fixture("block/drop_column.sql")

    assert result.status == "BLOCK"
    assert [finding.rule_id for finding in result.findings] == ["SG-009"]


def test_truncate_is_sg009_block(scan_sql_fixture) -> None:
    result: ScanResult = scan_sql_fixture("block/truncate.sql")

    assert result.status == "BLOCK"
    assert [finding.rule_id for finding in result.findings] == ["SG-009"]


def test_delete_without_where_is_sg009_block(scan_sql_fixture) -> None:
    result: ScanResult = scan_sql_fixture("block/delete_all.sql")

    assert result.status == "BLOCK"
    assert [finding.rule_id for finding in result.findings] == ["SG-009"]


def test_vacuum_full_and_reindex_are_sg008_blocks(scan_sql_fixture) -> None:
    vacuum: ScanResult = scan_sql_fixture("block/vacuum_full.sql")
    reindex: ScanResult = scan_sql_fixture("block/reindex.sql")

    assert vacuum.status == "BLOCK"
    assert [finding.rule_id for finding in vacuum.findings] == ["SG-008"]
    assert reindex.status == "BLOCK"
    assert [finding.rule_id for finding in reindex.findings] == ["SG-008"]

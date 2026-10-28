from __future__ import annotations

import json

from typer.testing import CliRunner

from safegate.cli import app
from safegate.config import SafegateConfig
from safegate.parser.postgres import parse_postgres
from safegate.scan import ScanResult

runner = CliRunner()


def test_malformed_fixture_is_unknown_with_exit_two(fixture_path) -> None:
    result = runner.invoke(
        app,
        ["scan", str(fixture_path("block/malformed.sql")), "--format", "json"],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "UNKNOWN"
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["rule_id"] == "PARSER-001"
    assert payload["status"] != "SAFE"


def test_empty_and_comment_only_fixture_is_safe(fixture_path) -> None:
    result = runner.invoke(
        app,
        ["scan", str(fixture_path("safe/empty_comments.sql")), "--format", "json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "SAFE"
    assert payload["findings"] == []


def test_begin_commit_context_spans_the_whole_file(
    scan_sql_fixture,
) -> None:
    result: ScanResult = scan_sql_fixture(
        "block/concurrent_in_tx.sql",
        config=SafegateConfig(transactional=False),
    )

    assert result.status == "BLOCK"
    assert [finding.rule_id for finding in result.findings] == ["SG-010"]


def test_multiple_statement_source_line_is_mapped_from_ast_tokens(
    read_sql_fixture,
) -> None:
    parsed = parse_postgres(
        read_sql_fixture("block/multiple_statements.sql"),
        file="tests/fixtures/block/multiple_statements.sql",
        transactional=False,
    )

    index_statement = next(
        item
        for item in parsed.statements
        if type(item.statement).__name__ == "IndexStmt"
    )
    assert index_statement.location.line == 4
    assert index_statement.location.column == 1


def test_dollar_quoted_body_keywords_do_not_trigger_rules(scan_sql_fixture) -> None:
    result: ScanResult = scan_sql_fixture(
        "safe/dollar_quoted_body.sql",
        config=SafegateConfig(transactional=False),
    )

    assert result.status == "SAFE"
    assert result.findings == ()

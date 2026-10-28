from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from safegate.cli import app
from safegate.scan import ScanResult

runner = CliRunner()


def _run(path: Path, *options: str) -> tuple[int, dict[str, object], str]:
    result = runner.invoke(app, ["scan", str(path), "--format", "json", *options])
    payload = json.loads(result.stdout)
    return result.exit_code, payload, result.stdout


def test_four_line_create_index_is_blocked(
    fixture_path,
) -> None:
    code, payload, _ = _run(fixture_path("block/multi_line_index.sql"))

    assert code == 1
    assert payload["status"] == "BLOCK"
    assert [finding["rule_id"] for finding in payload["findings"]] == ["SG-001"]


def test_comment_text_does_not_create_index_finding(fixture_path) -> None:
    code, payload, _ = _run(fixture_path("safe/comment_fake.sql"))

    assert code == 0
    assert payload["status"] == "SAFE"
    assert payload["findings"] == []


def test_quoted_sql_keywords_are_identifiers_not_statements(fixture_path) -> None:
    code, payload, _ = _run(fixture_path("safe/quoted_identifier.sql"))

    assert code == 0
    assert payload["status"] == "SAFE"
    assert payload["findings"] == []


def test_concurrent_index_outside_transaction_is_safe(
    fixture_path,
    monkeypatch,
    tmp_path,
) -> None:
    (tmp_path / ".safegate.toml").write_text(
        "transactional = false\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)

    code, payload, _ = _run(fixture_path("safe/concurrent_safe.sql"))

    assert code == 0
    assert payload["status"] == "SAFE"
    assert payload["findings"] == []


def test_concurrent_index_inside_explicit_transaction_is_sg010_block(
    fixture_path,
    monkeypatch,
    tmp_path,
) -> None:
    (tmp_path / ".safegate.toml").write_text(
        "transactional = false\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)

    code, payload, _ = _run(fixture_path("block/concurrent_in_tx.sql"))

    assert code == 1
    assert payload["status"] == "BLOCK"
    assert [finding["rule_id"] for finding in payload["findings"]] == ["SG-010"]


def test_unique_index_without_concurrently_is_sg001_block(fixture_path) -> None:
    code, payload, _ = _run(fixture_path("block/unique_index.sql"))

    assert code == 1
    assert payload["status"] == "BLOCK"
    assert [finding["rule_id"] for finding in payload["findings"]] == ["SG-001"]


def test_add_unique_constraint_is_sg003_block(fixture_path) -> None:
    code, payload, _ = _run(fixture_path("block/add_constraint_unique.sql"))

    assert code == 1
    assert payload["status"] == "BLOCK"
    assert [finding["rule_id"] for finding in payload["findings"]] == ["SG-003"]


def test_foreign_key_not_valid_is_not_blocked_by_sg007(fixture_path) -> None:
    code, payload, _ = _run(fixture_path("safe/fk_not_valid.sql"))

    assert code == 0
    assert payload["status"] == "SAFE"
    assert all(finding["rule_id"] != "SG-007" for finding in payload["findings"])


def test_drop_index_without_concurrently_is_sg002_block(fixture_path) -> None:
    code, payload, _ = _run(fixture_path("block/drop_index.sql"))

    assert code == 1
    assert payload["status"] == "BLOCK"
    assert [finding["rule_id"] for finding in payload["findings"]] == ["SG-002"]


def test_rule_configuration_can_disable_rule(
    scan_sql_fixture,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / ".safegate.toml"
    config_path.write_text(
        '[rules."SG-001"]\nenabled = false\n',
        encoding="utf-8",
    )
    from safegate.config import load_config

    config = load_config(config_path)
    result: ScanResult = scan_sql_fixture("block/multi_line_index.sql", config=config)

    assert result.status == "SAFE"
    assert result.findings == ()


def test_rule_configuration_allowlist_matches_object(
    scan_sql_fixture,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / ".safegate.toml"
    config_path.write_text(
        '[rules."SG-001"]\nallowlist = ["widgets"]\n',
        encoding="utf-8",
    )
    from safegate.config import load_config

    result: ScanResult = scan_sql_fixture(
        "block/multi_line_index.sql",
        config=load_config(config_path),
    )

    assert result.status == "SAFE"
    assert result.findings == ()


def test_rule_severity_override_changes_severity_not_decision(
    scan_sql_fixture,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / ".safegate.toml"
    config_path.write_text(
        '[rules."SG-001"]\nseverity = "low"\n',
        encoding="utf-8",
    )
    from safegate.config import load_config

    result: ScanResult = scan_sql_fixture(
        "block/multi_line_index.sql",
        config=load_config(config_path),
    )

    assert result.status == "BLOCK"
    assert result.findings[0].decision == "block"
    assert result.findings[0].severity == "low"

from __future__ import annotations

from safegate.scan import ScanResult


def test_add_column_default_is_review(scan_sql_fixture) -> None:
    result: ScanResult = scan_sql_fixture("review/add_column_default.sql")

    assert result.status == "REVIEW"
    assert [finding.rule_id for finding in result.findings] == ["SG-004"]


def test_set_not_null_is_review(scan_sql_fixture) -> None:
    result: ScanResult = scan_sql_fixture("review/set_not_null.sql")

    assert result.status == "REVIEW"
    assert [finding.rule_id for finding in result.findings] == ["SG-005"]


def test_alter_column_type_is_review(scan_sql_fixture) -> None:
    result: ScanResult = scan_sql_fixture("review/alter_column_type.sql")

    assert result.status == "REVIEW"
    assert [finding.rule_id for finding in result.findings] == ["SG-006"]


def test_add_foreign_key_without_not_valid_is_review(scan_sql_fixture) -> None:
    result: ScanResult = scan_sql_fixture("review/add_foreign_key.sql")

    assert result.status == "REVIEW"
    assert [finding.rule_id for finding in result.findings] == ["SG-007"]


def test_target_postgres_version_is_present_in_default_review(scan_sql_fixture) -> None:
    result: ScanResult = scan_sql_fixture("review/add_column_default.sql")

    assert "PostgreSQL 16" in result.findings[0].message
    assert "not asserted" in result.findings[0].evidence

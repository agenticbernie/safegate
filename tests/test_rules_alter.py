from __future__ import annotations

from safegate.config import SafegateConfig
from safegate.scan import ScanResult, scan_sql


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


def test_default_classification_never_removes_review_or_lock() -> None:
    result = scan_sql(
        "ALTER TABLE public.t ADD COLUMN x timestamptz DEFAULT pg_catalog.now()",
        file="m.sql",
    )
    finding = result.findings[0]
    assert result.status == "REVIEW"
    assert finding.default_volatility == "stable"
    assert finding.lock_impact[0].required_mode == "ACCESS EXCLUSIVE"
    assert finding.lock_impact[0].rewrite == "unknown"
    other = scan_sql(
        "ALTER TABLE public.t ADD COLUMN x timestamptz DEFAULT pg_catalog.now()",
        file="m.sql",
        config=SafegateConfig(pg_version=15),
    )
    assert other.findings[0].default_volatility == "unknown"
    assert other.findings[0].lock_impact[0].required_mode is None


def test_multiple_defaults_do_not_claim_single_volatility() -> None:
    result = scan_sql(
        "ALTER TABLE t ADD COLUMN a timestamptz DEFAULT pg_catalog.now(), ADD COLUMN b timestamptz DEFAULT pg_catalog.clock_timestamp()",
        file="m.sql",
    )
    assert result.findings[0].default_volatility == "unknown"


def test_type_target_alone_never_proves_a_conversion() -> None:
    result = scan_sql("ALTER TABLE public.t ALTER COLUMN n TYPE bigint", file="m.sql")
    assert result.status == "REVIEW"
    assert result.findings[0].lock_impact[0].required_mode == "ACCESS EXCLUSIVE"
    assert result.findings[0].lock_impact[0].rewrite == "unknown"

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from safegate.cli import app
from safegate.config import RuleConfig, SafegateConfig
from safegate.parser.postgres import parse_postgres
from safegate.report import ScanReport
from safegate.rules.base import AnalysisContext
from safegate.rules.destructive import DestructiveStatementRule
from safegate.scan import ScanResult, scan_sql

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
    impact = result.findings[0].lock_impact[0]
    assert impact.required_mode == "ACCESS EXCLUSIVE"
    assert impact.plain_read_conflict and impact.ordinary_write_conflict
    assert impact.rewrite == impact.runtime_contention == "unknown"


def test_drop_column_is_sg009_block(scan_sql_fixture) -> None:
    result: ScanResult = scan_sql_fixture("block/drop_column.sql")

    assert result.status == "BLOCK"
    assert [finding.rule_id for finding in result.findings] == ["SG-009"]


def test_truncate_is_sg009_block(scan_sql_fixture) -> None:
    result: ScanResult = scan_sql_fixture("block/truncate.sql")

    assert result.status == "BLOCK"
    assert [finding.rule_id for finding in result.findings] == ["SG-009"]
    assert result.findings[0].lock_impact[0].required_mode == "ACCESS EXCLUSIVE"


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


def test_direct_rule_evaluation_includes_drop_table_lock() -> None:
    parsed = parse_postgres("DROP TABLE public.old_sessions;", file="migration.sql")
    finding = DestructiveStatementRule().evaluate(
        parsed.statements[0], AnalysisContext()
    )[0]
    assert finding.lock_impact[0].relation == "public.old_sessions"
    assert finding.lock_impact[0].required_mode == "ACCESS EXCLUSIVE"


@pytest.mark.parametrize(
    "sql",
    [
        "MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN UPDATE SET x=s.x",
        "MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN DELETE",
        "MERGE INTO t USING s ON t.id=s.id WHEN NOT MATCHED THEN INSERT (id) VALUES (s.id)",
        "INSERT INTO t(id,x) VALUES (1,2) ON CONFLICT (id) DO UPDATE SET x=excluded.x",
        "INSERT INTO t(id,x) SELECT id,x FROM s ON CONFLICT (id) DO UPDATE SET x=excluded.x WHERE false",
        "UPDATE t SET x=s.x FROM s WHERE t.id=s.id",
        "DELETE FROM t USING s WHERE t.id=s.id",
    ],
)
def test_dml_unknown_scope_is_review_with_row_exclusive_lock(sql: str) -> None:
    result = scan_sql(sql, file="migration.sql")
    assert result.status == "REVIEW"
    finding = result.findings[0]
    assert finding.rule_id == "SG-009" and finding.decision == "review"
    impact = finding.lock_impact[0]
    assert impact.required_mode == "ROW EXCLUSIVE"
    assert (
        impact.plain_read_conflict is False and impact.ordinary_write_conflict is False
    )
    assert impact.rewrite == impact.runtime_contention == "unknown"


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO t(id) VALUES (1) ON CONFLICT DO NOTHING",
        "MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN DO NOTHING",
    ],
)
def test_do_nothing_has_no_destructive_finding(sql: str) -> None:
    result = scan_sql(sql, file="migration.sql")
    assert result.status == "SAFE"
    assert not any(f.rule_id == "SG-009" for f in result.findings)


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE t SET x=s.x FROM s",
        "DELETE FROM t USING s",
        "UPDATE t SET x=s.x FROM s WHERE true",
        "DELETE FROM t USING s WHERE true",
    ],
)
def test_joined_dml_does_not_downgrade_existing_unbounded_block(sql: str) -> None:
    assert scan_sql(sql, file="migration.sql").findings[0].decision == "block"


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE t SET x=s.x FROM s WHERE false",
        "DELETE FROM t USING s WHERE false",
    ],
)
def test_joined_dml_false_predicate_remains_a_noop(sql: str) -> None:
    assert scan_sql(sql, file="migration.sql").status == "SAFE"


@pytest.mark.parametrize(
    "sql",
    [
        "DROP TABLE public.a, public.b",
        "TRUNCATE public.a, public.b",
    ],
)
def test_multiple_ddl_targets_have_separate_lock_impacts(sql: str) -> None:
    impacts = scan_sql(sql, file="migration.sql").findings[0].lock_impact
    assert [impact.relation for impact in impacts] == ["public.a", "public.b"]
    assert all(impact.required_mode == "ACCESS EXCLUSIVE" for impact in impacts)


def test_partial_allowlist_cannot_suppress_unallowlisted_drop() -> None:
    policy = SafegateConfig(rules={"SG-009": RuleConfig(allowlist=("public.a",))})
    result = scan_sql(
        "DROP TABLE public.a, public.b", file="migration.sql", config=policy
    )
    assert result.status == "BLOCK"
    assert len(result.findings[0].lock_impact) == 2


def test_all_allowlisted_targets_suppress_drop() -> None:
    policy = SafegateConfig(
        rules={"SG-009": RuleConfig(allowlist=("public.a", "public.b"))}
    )
    assert (
        scan_sql(
            "DROP TABLE public.a, public.b", file="migration.sql", config=policy
        ).status
        == "SAFE"
    )


@pytest.mark.parametrize(
    "sql",
    [
        "MERGE INTO public.t USING s ON t.id=s.id WHEN MATCHED THEN DELETE",
        "INSERT INTO public.t(id) VALUES(1) ON CONFLICT(id) DO UPDATE SET id=excluded.id",
    ],
)
def test_new_dml_respects_sg009_policy(sql: str) -> None:
    disabled = SafegateConfig(rules={"SG-009": RuleConfig(enabled=False)})
    allowed = SafegateConfig(rules={"SG-009": RuleConfig(allowlist=("public.t",))})
    assert scan_sql(sql, file="migration.sql", config=disabled).status == "SAFE"
    assert scan_sql(sql, file="migration.sql", config=allowed).status == "SAFE"


def test_drop_if_exists_marks_lock_conditional() -> None:
    impact = (
        scan_sql("DROP TABLE IF EXISTS t", file="migration.sql")
        .findings[0]
        .lock_impact[0]
    )
    assert impact.required_mode == "ACCESS EXCLUSIVE"
    assert impact.evidence_confidence == "conditional"
    assert impact.assumptions == ("if the table exists",)


def test_sg009_fixture_v1_compatibility_and_v2_lock_impacts(fixture_path) -> None:
    path = str(fixture_path("sg009_dml_expansion.sql"))
    v1 = runner.invoke(app, ["scan", path, "--format", "json"])
    v2 = runner.invoke(
        app, ["scan", path, "--format", "json", "--report-schema", "2.0"]
    )
    legacy, rich = json.loads(v1.stdout), json.loads(v2.stdout)
    ScanReport.model_validate_json(v1.stdout)
    assert v1.exit_code == v2.exit_code == 1
    assert legacy["schema_version"] == "1.0" and rich["schema_version"] == "2.0"
    assert [f["decision"] for f in rich["findings"]] == [
        "review",
        "review",
        "review",
        "review",
        "block",
    ]
    assert all("lock_impact" not in f for f in legacy["findings"])
    assert [f["lock_impact"][0]["required_mode"] for f in rich["findings"]] == [
        "ROW EXCLUSIVE"
    ] * 4 + ["ACCESS EXCLUSIVE"]


def test_review_fail_on_policy_and_deterministic_v2(tmp_path: Path) -> None:
    path = tmp_path / "upsert.sql"
    path.write_text(
        "INSERT INTO t(id) VALUES(1) ON CONFLICT(id) DO UPDATE SET id=excluded.id;",
        encoding="utf-8",
    )
    args = ["scan", str(path), "--format", "json", "--report-schema", "2.0"]
    first = runner.invoke(app, args)
    second = runner.invoke(app, args)
    strict = runner.invoke(app, [*args, "--fail-on", "review"])
    assert first.exit_code == second.exit_code == 0 and strict.exit_code == 1
    assert first.stdout == second.stdout == strict.stdout


def test_unknown_pg_version_keeps_lock_impact_array_but_not_claims() -> None:
    result = scan_sql(
        "DROP TABLE public.t",
        file="migration.sql",
        config=SafegateConfig(pg_version=15),
    )
    assert result.status == "BLOCK"
    assert result.findings[0].lock_impact[0].required_mode is None

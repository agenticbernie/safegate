from __future__ import annotations

import pytest
from pglast import parse_sql

from safegate.rules.conversion_matrix import ColumnType, classify_conversion
from safegate.rules.pg16_behavior import analyze_statement, lock_conflicts
from safegate.rules.volatility_registry import classify_default


def _node(sql: str) -> object:
    return parse_sql(sql)[0].stmt


def test_complete_pg16_table_lock_conflict_matrix() -> None:
    modes = (
        "ACCESS SHARE",
        "ROW SHARE",
        "ROW EXCLUSIVE",
        "SHARE UPDATE EXCLUSIVE",
        "SHARE",
        "SHARE ROW EXCLUSIVE",
        "EXCLUSIVE",
        "ACCESS EXCLUSIVE",
    )
    rows = (
        "00000001",
        "00000011",
        "00001111",
        "00011111",
        "00110111",
        "00111111",
        "01111111",
        "11111111",
    )
    for mode, row in zip(modes, rows, strict=True):
        assert (
            "".join("1" if lock_conflicts(mode, other) else "0" for other in modes)
            == row
        )


@pytest.mark.parametrize(
    ("sql", "mode", "reads", "writes"),
    [
        ("CREATE INDEX i ON public.t (id)", "SHARE", False, True),
        (
            "CREATE INDEX CONCURRENTLY i ON public.t (id)",
            "SHARE UPDATE EXCLUSIVE",
            False,
            False,
        ),
        ("DROP INDEX i", "ACCESS EXCLUSIVE", True, True),
        ("DROP INDEX CONCURRENTLY i", "SHARE UPDATE EXCLUSIVE", False, False),
        ("ALTER TABLE public.t ADD COLUMN x int", "ACCESS EXCLUSIVE", True, True),
        (
            "ALTER TABLE public.t ADD CONSTRAINT f FOREIGN KEY (x) REFERENCES public.p (x)",
            "SHARE ROW EXCLUSIVE",
            False,
            True,
        ),
        ("UPDATE public.t SET x=1", "ROW EXCLUSIVE", False, False),
    ],
)
def test_lock_conflict_matrix(sql: str, mode: str, reads: bool, writes: bool) -> None:
    impact = analyze_statement(_node(sql), pg_version=16)[0]
    assert (
        impact.required_mode,
        impact.plain_read_conflict,
        impact.ordinary_write_conflict,
    ) == (mode, reads, writes)
    assert impact.runtime_contention == "unknown"


def test_foreign_key_and_mixed_alter_track_secondary_and_strictest_lock() -> None:
    impacts = analyze_statement(
        _node(
            "ALTER TABLE public.t ADD COLUMN y int, ADD CONSTRAINT f FOREIGN KEY (x) REFERENCES public.p(x)"
        ),
        pg_version=16,
    )
    assert [(i.relation, i.required_mode) for i in impacts] == [
        ("public.t", "ACCESS EXCLUSIVE"),
        ("public.p", "SHARE ROW EXCLUSIVE"),
    ]


def test_inline_foreign_key_tracks_referenced_relation() -> None:
    impacts = analyze_statement(
        _node("ALTER TABLE public.t ADD COLUMN pid int REFERENCES public.p(id)"),
        pg_version=16,
    )
    assert [(i.relation, i.required_mode) for i in impacts] == [
        ("public.t", "ACCESS EXCLUSIVE"),
        ("public.p", "SHARE ROW EXCLUSIVE"),
    ]


def test_multiple_index_drops_keep_each_unknown_table() -> None:
    impacts = analyze_statement(_node("DROP INDEX public.i, public.j"), pg_version=16)
    assert len(impacts) == 2
    assert all(
        i.relation is None and i.required_mode == "ACCESS EXCLUSIVE" for i in impacts
    )


def test_self_referencing_constraint_does_not_weaken_target_lock() -> None:
    impacts = analyze_statement(
        _node("ALTER TABLE public.t ADD COLUMN pid int REFERENCES public.t(id)"),
        pg_version=16,
    )
    assert len(impacts) == 1
    assert impacts[0].required_mode == "ACCESS EXCLUSIVE"


def test_if_not_exists_makes_secondary_fk_lock_conditional() -> None:
    impacts = analyze_statement(
        _node("ALTER TABLE t ADD COLUMN IF NOT EXISTS pid int REFERENCES p(id)"),
        pg_version=16,
    )
    assert impacts[0].required_mode == "ACCESS EXCLUSIVE"
    assert impacts[1].evidence_confidence == "conditional"


def test_unrecognized_alter_and_other_pg_version_are_unknown() -> None:
    assert (
        analyze_statement(_node("ALTER TABLE t SET (fillfactor=70)"), pg_version=16)[
            0
        ].required_mode
        is None
    )
    assert (
        analyze_statement(_node("CREATE INDEX i ON t(x)"), pg_version=15)[
            0
        ].required_mode
        is None
    )


@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ("pg_catalog.clock_timestamp()", "volatile"),
        ("pg_catalog.now()", "stable"),
        ("clock_timestamp()", "unknown"),
        ("custom()", "unknown"),
        (
            "CASE WHEN false THEN pg_catalog.clock_timestamp() ELSE pg_catalog.now() END",
            "unknown",
        ),
        ("pg_catalog.now() + custom()", "unknown"),
    ],
)
def test_default_volatility_is_conservative(expr: str, expected: str) -> None:
    command = _node(f"ALTER TABLE t ADD COLUMN x timestamptz DEFAULT {expr}").cmds[0]
    raw = command.def_.constraints[0].raw_expr
    assert classify_default(raw, pg_version=16) == expected
    assert classify_default(raw, pg_version=15) == "unknown"


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        (ColumnType("varchar", 10), ColumnType("varchar", 20), "not_required"),
        (ColumnType("varchar", 20), ColumnType("varchar", 10), "required"),
        (ColumnType("varchar", 10), ColumnType("varchar", None), "not_required"),
        (ColumnType("varchar", None), ColumnType("varchar", 10), "required"),
        (ColumnType("integer", None), ColumnType("bigint", None), "required"),
        (ColumnType("text", None), ColumnType("varchar", None), "not_required"),
        (None, ColumnType("bigint", None), "unknown"),
        (ColumnType("custom", None), ColumnType("bigint", None), "unknown"),
    ],
)
def test_conversion_requires_proven_source_and_typmods(old, new, expected: str) -> None:
    assert classify_conversion(old, new, pg_version=16, identity_using=True) == expected
    assert (
        classify_conversion(old, new, pg_version=15, identity_using=True) == "unknown"
    )
    assert (
        classify_conversion(old, new, pg_version=16, identity_using=False) == "unknown"
    )

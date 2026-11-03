"""Tiny PG16 registry for expressions whose raw syntax resolves unambiguously."""

from __future__ import annotations

from typing import Literal

Volatility = Literal["immutable", "stable", "volatile", "unknown"]

# Zero-argument, explicitly pg_catalog-qualified built-ins only.
# https://github.com/postgres/postgres/blob/REL_16_STABLE/src/include/catalog/pg_proc.dat#L2548-L2560
# https://www.postgresql.org/docs/16/xfunc-volatility.html
_PG16_FUNCTIONS: dict[tuple[str, str], Volatility] = {
    ("pg_catalog", "now"): "stable",
    ("pg_catalog", "transaction_timestamp"): "stable",
    ("pg_catalog", "statement_timestamp"): "stable",
    ("pg_catalog", "clock_timestamp"): "volatile",
}


def classify_default(expression: object, *, pg_version: int) -> Volatility:
    """Classify the raw expression only, not implicit casts or a heap rewrite."""
    if pg_version != 16 or type(expression).__name__ != "FuncCall":
        return "unknown"
    parts = tuple(
        getattr(part, "sval", "") for part in getattr(expression, "funcname", ())
    )
    if len(parts) != 2 or getattr(expression, "args", None):
        return "unknown"
    if any(
        bool(getattr(expression, field, False))
        for field in ("agg_star", "agg_distinct", "agg_within_group", "func_variadic")
    ):
        return "unknown"
    return _PG16_FUNCTIONS.get((parts[0], parts[1]), "unknown")

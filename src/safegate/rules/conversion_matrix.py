"""Conservative PG16 heap rewrite expectations for independently known types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Rewrite = Literal["required", "not_required", "unknown"]


@dataclass(frozen=True, slots=True)
class ColumnType:
    """A proven built-in type; None typmod means explicitly unbounded."""

    name: str
    typmod: int | None


def classify_conversion(
    old: ColumnType | None,
    new: ColumnType | None,
    *,
    pg_version: int,
    identity_using: bool,
) -> Rewrite:
    # https://www.postgresql.org/docs/16/sql-altertable.html
    # https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/utils/adt/varchar.c#L525-L557
    # https://github.com/postgres/postgres/blob/REL_16_STABLE/src/include/catalog/pg_cast.dat
    # The input types must be verified independently; SQL ALTER provides no old type.
    if pg_version != 16 or old is None or new is None or not identity_using:
        return "unknown"
    for col in (old, new):
        if col.name not in {"varchar", "text", "integer", "bigint"}:
            return "unknown"
        if col.name != "varchar" and col.typmod is not None:
            return "unknown"
        if col.name == "varchar" and col.typmod is not None and col.typmod < 1:
            return "unknown"
    if old.name in {"integer", "bigint"} or new.name in {"integer", "bigint"}:
        if old.name == new.name:
            return "not_required"
        if old.name == "integer" and new.name == "bigint":
            return "required"
        return "unknown"
    if new.name == "text" or new.typmod is None:
        return "not_required"
    if old.name == "varchar" and old.typmod is not None and old.typmod <= new.typmod:
        return "not_required"
    return "required"

"""Static table-lock facts, not observations of contention."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from safegate.rules.base import qualified_name

LockMode = Literal[
    "ACCESS SHARE",
    "ROW SHARE",
    "ROW EXCLUSIVE",
    "SHARE UPDATE EXCLUSIVE",
    "SHARE",
    "SHARE ROW EXCLUSIVE",
    "EXCLUSIVE",
    "ACCESS EXCLUSIVE",
]
Evidence = Literal["verified", "conditional", "unknown"]

# https://www.postgresql.org/docs/16/explicit-locking.html#LOCKING-TABLES
# https://www.postgresql.org/docs/16/explicit-locking.html#TABLE-LOCK-COMPATIBILITY
_CONFLICTS: dict[LockMode, frozenset[LockMode]] = {
    "ACCESS SHARE": frozenset({"ACCESS EXCLUSIVE"}),
    "ROW SHARE": frozenset({"EXCLUSIVE", "ACCESS EXCLUSIVE"}),
    "ROW EXCLUSIVE": frozenset(
        {"SHARE", "SHARE ROW EXCLUSIVE", "EXCLUSIVE", "ACCESS EXCLUSIVE"}
    ),
    "SHARE UPDATE EXCLUSIVE": frozenset(
        {
            "SHARE UPDATE EXCLUSIVE",
            "SHARE",
            "SHARE ROW EXCLUSIVE",
            "EXCLUSIVE",
            "ACCESS EXCLUSIVE",
        }
    ),
    "SHARE": frozenset(
        {
            "ROW EXCLUSIVE",
            "SHARE UPDATE EXCLUSIVE",
            "SHARE ROW EXCLUSIVE",
            "EXCLUSIVE",
            "ACCESS EXCLUSIVE",
        }
    ),
    "SHARE ROW EXCLUSIVE": frozenset(
        {
            "ROW EXCLUSIVE",
            "SHARE UPDATE EXCLUSIVE",
            "SHARE",
            "SHARE ROW EXCLUSIVE",
            "EXCLUSIVE",
            "ACCESS EXCLUSIVE",
        }
    ),
    "EXCLUSIVE": frozenset(
        {
            "ROW SHARE",
            "ROW EXCLUSIVE",
            "SHARE UPDATE EXCLUSIVE",
            "SHARE",
            "SHARE ROW EXCLUSIVE",
            "EXCLUSIVE",
            "ACCESS EXCLUSIVE",
        }
    ),
    "ACCESS EXCLUSIVE": frozenset(
        {
            "ACCESS SHARE",
            "ROW SHARE",
            "ROW EXCLUSIVE",
            "SHARE UPDATE EXCLUSIVE",
            "SHARE",
            "SHARE ROW EXCLUSIVE",
            "EXCLUSIVE",
            "ACCESS EXCLUSIVE",
        }
    ),
}


def lock_conflicts(first: LockMode, second: LockMode) -> bool:
    """Whether two transactions' table locks conflict on the same relation."""
    return second in _CONFLICTS[first]


@dataclass(frozen=True, slots=True)
class LockImpact:
    relation: str | None
    required_mode: LockMode | None
    plain_read_conflict: bool | None
    ordinary_write_conflict: bool | None
    runtime_contention: Literal["unknown"] = "unknown"
    rewrite: Literal["required", "not_required", "unknown"] = "unknown"
    evidence_confidence: Evidence = "unknown"
    assumptions: tuple[str, ...] = ()


def _impact(
    relation: str | None,
    mode: LockMode | None,
    *,
    conditional: bool = False,
    assumptions: tuple[str, ...] = (),
) -> LockImpact:
    reads = lock_conflicts(mode, "ACCESS SHARE") if mode is not None else None
    writes = lock_conflicts(mode, "ROW EXCLUSIVE") if mode is not None else None
    confidence: Evidence = (
        "unknown" if mode is None else "conditional" if conditional else "verified"
    )
    return LockImpact(
        relation,
        mode,
        reads,
        writes,
        evidence_confidence=confidence,
        assumptions=assumptions,
    )


def analyze_statement(node: object, *, pg_version: int) -> tuple[LockImpact, ...]:
    """Return supported PG16 target-table impacts; catalog state is never queried."""
    kind = type(node).__name__
    if kind not in {
        "IndexStmt",
        "DropStmt",
        "AlterTableStmt",
        "UpdateStmt",
        "DeleteStmt",
        "InsertStmt",
        "MergeStmt",
    }:
        return ()
    relation = qualified_name(getattr(node, "relation", None))
    if pg_version != 16:
        return (_impact(relation, None),)
    # https://www.postgresql.org/docs/16/sql-createindex.html
    if kind == "IndexStmt":
        if getattr(node, "concurrent", False):
            return (
                _impact(
                    relation,
                    "SHARE UPDATE EXCLUSIVE",
                    conditional=True,
                    assumptions=("non-temporary table; concurrent build is supported",),
                ),
            )
        return (_impact(relation, "SHARE"),)
    # https://www.postgresql.org/docs/16/sql-dropindex.html
    # https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/catalog/index.c#L2039-L2052
    if kind == "DropStmt":
        if getattr(getattr(node, "removeType", None), "name", "") != "OBJECT_INDEX":
            return ()
        mode: LockMode = (
            "SHARE UPDATE EXCLUSIVE"
            if getattr(node, "concurrent", False)
            else "ACCESS EXCLUSIVE"
        )
        # Each index can belong to a different table; the AST does not resolve it.
        return tuple(
            _impact(None, mode) for _ in (getattr(node, "objects", ()) or (None,))
        )
    if kind in {"UpdateStmt", "DeleteStmt", "InsertStmt", "MergeStmt"}:
        return (_impact(relation, "ROW EXCLUSIVE"),)
    # https://www.postgresql.org/docs/16/sql-altertable.html
    modes: list[LockMode | None] = []
    referenced: list[tuple[str | None, bool]] = []
    for cmd in getattr(node, "cmds", ()) or ():
        subtype = getattr(getattr(cmd, "subtype", None), "name", "")
        if subtype in {
            "AT_AddColumn",
            "AT_AlterColumnType",
            "AT_SetNotNull",
            "AT_DropColumn",
        }:
            modes.append("ACCESS EXCLUSIVE")
            if subtype == "AT_AddColumn":
                # https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/commands/tablecmds.c#L8722-L8729
                for constraint in (
                    getattr(getattr(cmd, "def_", None), "constraints", ()) or ()
                ):
                    if (
                        getattr(getattr(constraint, "contype", None), "name", "")
                        == "CONSTR_FOREIGN"
                    ):
                        referenced.append(
                            (
                                qualified_name(getattr(constraint, "pktable", None)),
                                bool(getattr(cmd, "missing_ok", False)),
                            )
                        )
        elif subtype == "AT_AddConstraint":
            constraint = getattr(cmd, "def_", None)
            ctype = getattr(getattr(constraint, "contype", None), "name", "")
            if ctype == "CONSTR_FOREIGN":
                modes.append("SHARE ROW EXCLUSIVE")
                referenced.append(
                    (qualified_name(getattr(constraint, "pktable", None)), False)
                )
            elif ctype in {
                "CONSTR_CHECK",
                "CONSTR_PRIMARY",
                "CONSTR_UNIQUE",
                "CONSTR_EXCLUSION",
            }:
                modes.append("ACCESS EXCLUSIVE")
            else:
                modes.append(None)
        else:
            modes.append(None)
    if "ACCESS EXCLUSIVE" in modes:
        mode = "ACCESS EXCLUSIVE"
    elif modes and all(item == "SHARE ROW EXCLUSIVE" for item in modes):
        mode = "SHARE ROW EXCLUSIVE"
    else:
        return (
            _impact(relation, None),
            *(
                _impact(
                    ref,
                    "SHARE ROW EXCLUSIVE",
                    conditional=conditional,
                    assumptions=("column addition is not skipped",)
                    if conditional
                    else (),
                )
                for ref, conditional in referenced
            ),
        )
    return (
        _impact(relation, mode),
        *(
            _impact(
                ref,
                "SHARE ROW EXCLUSIVE",
                conditional=conditional,
                assumptions=("column addition is not skipped",) if conditional else (),
            )
            for ref, conditional in referenced
            if not (ref is not None and ref == relation)
        ),
    )

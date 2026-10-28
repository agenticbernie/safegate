from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from safegate.parser.postgres import ParsedStatement
from safegate.rules.base import (
    AnalysisContext,
    Decision,
    Finding,
    Severity,
    finding_for,
    qualified_name,
)

_UNKNOWN = object()


def _ddl_names(objects: object) -> tuple[str, ...]:
    names: list[str] = []
    if not isinstance(objects, tuple):
        return ()
    for item in objects:
        if not isinstance(item, tuple):
            continue
        parts = [getattr(part, "sval", None) for part in item]
        if parts and all(isinstance(part, str) and part for part in parts):
            names.append(".".join(part for part in parts if isinstance(part, str)))
    return tuple(names)


def _constant(node: Any) -> object:
    if type(node).__name__ != "A_Const":
        return _UNKNOWN
    if bool(getattr(node, "isnull", False)):
        return None
    value = getattr(node, "val", None)
    if value is None:
        return _UNKNOWN
    kind = type(value).__name__
    if kind == "Boolean":
        return bool(value.boolval)
    if kind == "Integer":
        return int(value.ival)
    if kind == "Float":
        try:
            return Decimal(value.fval)
        except (InvalidOperation, TypeError):
            return _UNKNOWN
    if kind == "String":
        return value.sval
    return _UNKNOWN


def _known_predicate(node: Any) -> bool | None:
    """Fold only small, literal predicates; never execute SQL expressions."""
    node_type = type(node).__name__
    if node_type == "A_Const":
        value = _constant(node)
        return value if isinstance(value, bool) else None

    if node_type == "BoolExpr":
        operator = getattr(getattr(node, "boolop", None), "name", "")
        values = [_known_predicate(value) for value in getattr(node, "args", ())]
        if operator == "NOT_EXPR" and len(values) == 1:
            return None if values[0] is None else not values[0]
        if operator == "AND_EXPR":
            if False in values:
                return False
            return True if values and all(value is True for value in values) else None
        if operator == "OR_EXPR":
            if True in values:
                return True
            return False if values and all(value is False for value in values) else None
        return None

    if node_type != "A_Expr":
        return None
    operator_parts = [getattr(part, "sval", "") for part in getattr(node, "name", ())]
    operator = "".join(operator_parts)
    left = _constant(getattr(node, "lexpr", None))
    right = _constant(getattr(node, "rexpr", None))
    if left is _UNKNOWN or right is _UNKNOWN or left is None or right is None:
        return None
    if isinstance(left, bool) and isinstance(right, bool):
        if operator in {"=", "=="}:
            return left == right
        if operator in {"<>", "!="}:
            return left != right
        return None

    if isinstance(left, str) and isinstance(right, str):
        if operator in {"=", "=="}:
            return left == right
        if operator in {"<>", "!="}:
            return left != right
        if operator == "<":
            return left < right
        if operator == ">":
            return left > right
        if operator == "<=":
            return left <= right
        if operator == ">=":
            return left >= right
        return None

    if (
        isinstance(left, (int, Decimal))
        and not isinstance(left, bool)
        and isinstance(right, (int, Decimal))
        and not isinstance(right, bool)
    ):
        numeric_left = Decimal(left)
        numeric_right = Decimal(right)
        if operator in {"=", "=="}:
            return numeric_left == numeric_right
        if operator in {"<>", "!="}:
            return numeric_left != numeric_right
        if operator == "<":
            return numeric_left < numeric_right
        if operator == ">":
            return numeric_left > numeric_right
        if operator == "<=":
            return numeric_left <= numeric_right
        if operator == ">=":
            return numeric_left >= numeric_right
    return None


class RewriteOperationRule:
    rule_id = "SG-008"

    def evaluate(
        self, statement: ParsedStatement, ctx: AnalysisContext
    ) -> list[Finding]:
        node = statement.statement
        node_type = type(node).__name__
        decision: Decision = "review"
        severity: Severity = "medium"
        message = (
            "This maintenance operation needs review for its target PostgreSQL version."
        )
        evidence = f"AST statement type: {node_type}."
        object_names: tuple[str, ...] = ()

        if node_type == "VacuumStmt":
            full = any(
                getattr(option, "defname", "") == "full" for option in node.options
            )
            if not full:
                return []
            decision = "block"
            severity = "high"
            message = "VACUUM FULL can require a disruptive table rewrite."
            evidence = "AST VacuumStmt: FULL option is present."
            relation_names = tuple(
                qualified_name(getattr(relation, "relation", None)) or ""
                for relation in getattr(node, "rels", ())
            )
            object_names = relation_names
        elif node_type == "ClusterStmt":
            evidence = "AST ClusterStmt: CLUSTER operation detected."
            object_names = (qualified_name(getattr(node, "relation", None)) or "",)
        elif node_type == "ReindexStmt":
            concurrent = any(
                getattr(parameter, "defname", "") == "concurrently"
                for parameter in (getattr(node, "params", ()) or ())
            )
            if concurrent:
                # TODO(research): Verify target-version and object-specific REINDEX behavior.
                evidence = "AST ReindexStmt: CONCURRENTLY option is present; support is unverified."
            else:
                decision = "block"
                severity = "high"
                message = (
                    "REINDEX without CONCURRENTLY may require a disruptive rewrite."
                )
                evidence = "AST ReindexStmt: CONCURRENTLY option is absent."
            object_names = (qualified_name(getattr(node, "relation", None)) or "",)
        else:
            return []

        finding = finding_for(
            statement=statement,
            ctx=ctx,
            rule_id=self.rule_id,
            severity=severity,
            decision=decision,
            message=message,
            recommendation=(
                "Schedule the operation outside the migration window and verify its exact behavior for the target PostgreSQL version."
            ),
            confidence=0.78,
            evidence=evidence,
            object_names=object_names,
        )
        return [finding] if finding is not None else []


class DestructiveStatementRule:
    rule_id = "SG-009"

    def evaluate(
        self, statement: ParsedStatement, ctx: AnalysisContext
    ) -> list[Finding]:
        node = statement.statement
        node_type = type(node).__name__
        object_names: tuple[str, ...] = ()
        decision: Decision = "block"
        message = "This destructive statement has no row or object scope."
        evidence = f"AST statement type: {node_type}."

        if node_type == "DropStmt":
            object_type = getattr(getattr(node, "removeType", None), "name", "")
            if object_type != "OBJECT_TABLE":
                return []
            object_names = _ddl_names(getattr(node, "objects", ()))
            message = "DROP TABLE removes a table and its data definition."
            evidence = "AST DropStmt: object type is table."
        elif node_type == "AlterTableStmt":
            dropped_column = any(
                getattr(getattr(command, "subtype", None), "name", "")
                == "AT_DropColumn"
                for command in getattr(node, "cmds", ())
            )
            if not dropped_column:
                return []
            object_names = (qualified_name(getattr(node, "relation", None)) or "",)
            message = "ALTER TABLE DROP COLUMN removes a column and its stored values."
            evidence = "AST AlterTableCmd: AT_DropColumn detected."
        elif node_type == "TruncateStmt":
            object_names = tuple(
                qualified_name(relation) or ""
                for relation in getattr(node, "relations", ())
            )
            message = "TRUNCATE removes all rows from the selected table or tables."
            evidence = "AST TruncateStmt detected."
        elif node_type in {"DeleteStmt", "UpdateStmt"}:
            relation = qualified_name(getattr(node, "relation", None))
            object_names = (relation or "",)
            where_clause = getattr(node, "whereClause", None)
            if where_clause is None:
                evidence = f"AST {node_type}: no WHERE clause."
            else:
                predicate = _known_predicate(where_clause)
                if predicate is False:
                    return []
                if predicate is True:
                    evidence = (
                        f"AST {node_type}: WHERE predicate constant-folded to true."
                    )
                else:
                    decision = "review"
                    message = f"{node_type.removesuffix('Stmt')} predicate row scope is unknown."
                    evidence = f"AST {node_type}: WHERE exists but its row scope cannot be proven statically."
        else:
            return []

        finding = finding_for(
            statement=statement,
            ctx=ctx,
            rule_id=self.rule_id,
            severity="high" if decision == "block" else "medium",
            decision=decision,
            message=message,
            recommendation=(
                "Limit the affected objects or rows, and require an explicit rollback or recovery plan before running."
            ),
            confidence=0.98 if decision == "block" else 0.55,
            evidence=evidence,
            object_names=object_names,
        )
        return [finding] if finding is not None else []

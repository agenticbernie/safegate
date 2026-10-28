from __future__ import annotations

from typing import Any

from safegate.parser.postgres import ParsedStatement
from safegate.rules.base import (
    AnalysisContext,
    Finding,
    finding_for,
    qualified_name,
)


def _drop_object_name(value: Any) -> str | None:
    if not isinstance(value, tuple):
        return None
    parts = [getattr(part, "sval", None) for part in value]
    if not parts or any(not isinstance(part, str) or not part for part in parts):
        return None
    return ".".join(part for part in parts if isinstance(part, str))


class CreateIndexRule:
    rule_id = "SG-001"

    def evaluate(
        self, statement: ParsedStatement, ctx: AnalysisContext
    ) -> list[Finding]:
        node = statement.statement
        if type(node).__name__ != "IndexStmt" or bool(
            getattr(node, "concurrent", False)
        ):
            return []
        finding = finding_for(
            statement=statement,
            ctx=ctx,
            rule_id=self.rule_id,
            severity="high",
            decision="block",
            message="CREATE INDEX may block writes; CONCURRENTLY is missing.",
            recommendation="Use CREATE INDEX CONCURRENTLY outside a transaction block.",
            confidence=0.98,
            evidence=(
                "AST IndexStmt: concurrently=false; "
                f"unique={bool(getattr(node, 'unique', False))}."
            ),
            object_names=(
                qualified_name(getattr(node, "relation", None)) or "",
                getattr(node, "idxname", None) or "",
            ),
        )
        return [finding] if finding is not None else []


class DropIndexRule:
    rule_id = "SG-002"

    def evaluate(
        self, statement: ParsedStatement, ctx: AnalysisContext
    ) -> list[Finding]:
        node = statement.statement
        if (
            type(node).__name__ != "DropStmt"
            or getattr(getattr(node, "removeType", None), "name", "") != "OBJECT_INDEX"
            or bool(getattr(node, "concurrent", False))
        ):
            return []
        names = tuple(
            name
            for name in (
                _drop_object_name(value) for value in getattr(node, "objects", ())
            )
            if name
        )
        if names and all(ctx.is_allowlisted(self.rule_id, (name,)) for name in names):
            return []
        finding = finding_for(
            statement=statement,
            ctx=ctx,
            rule_id=self.rule_id,
            severity="high",
            decision="block",
            message="DROP INDEX may block writes; CONCURRENTLY is missing.",
            recommendation="Use DROP INDEX CONCURRENTLY when dependencies and target PostgreSQL support permit it.",
            confidence=0.95,
            evidence="AST DropStmt: object type is index; concurrently=false.",
        )
        return [finding] if finding is not None else []


class ConcurrentIndexTransactionRule:
    rule_id = "SG-010"

    def evaluate(
        self, statement: ParsedStatement, ctx: AnalysisContext
    ) -> list[Finding]:
        node = statement.statement
        if (
            type(node).__name__ != "IndexStmt"
            or not bool(getattr(node, "concurrent", False))
            or not statement.in_transaction
        ):
            return []
        finding = finding_for(
            statement=statement,
            ctx=ctx,
            rule_id=self.rule_id,
            severity="high",
            decision="block",
            message="CREATE INDEX CONCURRENTLY cannot run inside a transaction block.",
            recommendation="Move this statement to a migration that runs outside a transaction block.",
            confidence=0.99,
            evidence="AST IndexStmt: concurrently=true; transaction context is active.",
            object_names=(
                qualified_name(getattr(node, "relation", None)) or "",
                getattr(node, "idxname", None) or "",
            ),
        )
        return [finding] if finding is not None else []

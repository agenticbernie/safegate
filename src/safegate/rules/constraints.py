from __future__ import annotations

from safegate.parser.postgres import ParsedStatement
from safegate.rules.base import AnalysisContext, Finding, finding_for, qualified_name


def _added_constraints(statement: object) -> tuple[object, ...]:
    if type(statement).__name__ != "AlterTableStmt":
        return ()
    found: list[object] = []
    for command in getattr(statement, "cmds", ()):
        subtype = getattr(getattr(command, "subtype", None), "name", "")
        constraint = getattr(command, "def_", None)
        if subtype == "AT_AddConstraint" and constraint is not None:
            found.append(constraint)
    return tuple(found)


class AddKeyConstraintRule:
    rule_id = "SG-003"

    def evaluate(
        self, statement: ParsedStatement, ctx: AnalysisContext
    ) -> list[Finding]:
        node = statement.statement
        constraints = _added_constraints(node)
        if not any(
            getattr(getattr(constraint, "contype", None), "name", "")
            in {"CONSTR_PRIMARY", "CONSTR_UNIQUE"}
            for constraint in constraints
        ):
            return []
        table = qualified_name(getattr(node, "relation", None))
        finding = finding_for(
            statement=statement,
            ctx=ctx,
            rule_id=self.rule_id,
            severity="high",
            decision="block",
            message="Adding PRIMARY KEY or UNIQUE creates an index inside ALTER TABLE.",
            recommendation=(
                "Create a unique index concurrently, then attach the constraint if the migration workflow supports it."
            ),
            confidence=0.96,
            evidence="AST AlterTableCmd: added PRIMARY KEY or UNIQUE constraint.",
            object_names=(table or "",),
        )
        return [finding] if finding is not None else []


class UnvalidatedConstraintRule:
    rule_id = "SG-007"

    def evaluate(
        self, statement: ParsedStatement, ctx: AnalysisContext
    ) -> list[Finding]:
        node = statement.statement
        constraints = _added_constraints(node)
        risky = [
            constraint
            for constraint in constraints
            if getattr(getattr(constraint, "contype", None), "name", "")
            in {"CONSTR_FOREIGN", "CONSTR_CHECK"}
            and not bool(getattr(constraint, "skip_validation", False))
        ]
        if not risky:
            return []
        table = qualified_name(getattr(node, "relation", None))
        types = sorted(
            {
                getattr(getattr(constraint, "contype", None), "name", "")
                for constraint in risky
            }
        )
        finding = finding_for(
            statement=statement,
            ctx=ctx,
            rule_id=self.rule_id,
            severity="medium",
            decision="review",
            message=(
                f"Adding this constraint without NOT VALID needs review for PostgreSQL {ctx.pg_version}."
            ),
            recommendation="Add the constraint with NOT VALID, then validate it in a separate step.",
            confidence=0.9,
            evidence=f"AST added constraint types: {', '.join(types)}; NOT VALID is absent.",
            object_names=(table or "",),
        )
        return [finding] if finding is not None else []

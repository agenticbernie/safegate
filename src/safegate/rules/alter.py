from __future__ import annotations

from safegate.parser.postgres import ParsedStatement
from safegate.rules.base import AnalysisContext, Finding, finding_for, qualified_name


def _alter_commands(statement: object) -> tuple[object, ...]:
    if type(statement).__name__ != "AlterTableStmt":
        return ()
    return tuple(getattr(statement, "cmds", ()))


def _column_constraints(column: object) -> tuple[object, ...]:
    if not column:
        return ()
    # pglast thường trả về None thay vì list rỗng cho các thuộc tính không có giá trị
    constraints = getattr(column, "constraints", None)
    return tuple(constraints) if constraints else ()


class AddColumnDefaultRule:
    rule_id = "SG-004"

    def evaluate(
        self, statement: ParsedStatement, ctx: AnalysisContext
    ) -> list[Finding]:
        node = statement.statement
        if type(node).__name__ != "AlterTableStmt":
            return []
        found = False
        for command in _alter_commands(node):
            if getattr(getattr(command, "subtype", None), "name", "") != "AT_AddColumn":
                continue
            column = getattr(command, "def_", None)
            if any(
                getattr(getattr(constraint, "contype", None), "name", "")
                == "CONSTR_DEFAULT"
                for constraint in _column_constraints(column)
            ):
                found = True
                break
        if not found:
            return []
        # TODO(research): Verify constant/immutable DEFAULT fast paths by target PG version.
        table = qualified_name(getattr(node, "relation", None))
        finding = finding_for(
            statement=statement,
            ctx=ctx,
            rule_id=self.rule_id,
            severity="medium",
            decision="review",
            message=f"ADD COLUMN DEFAULT behavior needs verification for PostgreSQL {ctx.pg_version}.",
            recommendation=(
                "Consider adding the column first, backfilling in batches, and setting the default after verifying the target PostgreSQL version."
            ),
            confidence=0.72,
            evidence=(
                f"AST AlterTableCmd adds a column with DEFAULT; target PostgreSQL={ctx.pg_version}; "
                "fast-path behavior is not asserted."
            ),
            object_names=(table or "",),
        )
        return [finding] if finding is not None else []


class SetNotNullRule:
    rule_id = "SG-005"

    def evaluate(
        self, statement: ParsedStatement, ctx: AnalysisContext
    ) -> list[Finding]:
        node = statement.statement
        commands = _alter_commands(node)
        risky = False
        for command in commands:
            subtype = getattr(getattr(command, "subtype", None), "name", "")
            if subtype == "AT_SetNotNull":
                risky = True
                break
            if subtype == "AT_AddColumn":
                column = getattr(command, "def_", None)
                if bool(getattr(column, "is_not_null", False)) or any(
                    getattr(getattr(constraint, "contype", None), "name", "")
                    == "CONSTR_NOTNULL"
                    for constraint in _column_constraints(column)
                ):
                    risky = True
                    break
        if not risky:
            return []
        table = qualified_name(getattr(node, "relation", None))
        finding = finding_for(
            statement=statement,
            ctx=ctx,
            rule_id=self.rule_id,
            severity="medium",
            decision="review",
            message="Setting NOT NULL may require validation against existing rows.",
            recommendation=(
                "Backfill first, add a CHECK NOT VALID, validate it, then set NOT NULL after confirming target-version behavior."
            ),
            confidence=0.78,
            evidence="AST AlterTableCmd sets or adds a NOT NULL constraint; table contents are unavailable.",
            object_names=(table or "",),
        )
        return [finding] if finding is not None else []


class AlterColumnTypeRule:
    rule_id = "SG-006"

    def evaluate(
        self, statement: ParsedStatement, ctx: AnalysisContext
    ) -> list[Finding]:
        node = statement.statement
        if not any(
            getattr(getattr(command, "subtype", None), "name", "")
            == "AT_AlterColumnType"
            for command in _alter_commands(node)
        ):
            return []
        # TODO(research): Build an evidence-backed conversion/rewrite matrix per PG version.
        table = qualified_name(getattr(node, "relation", None))
        finding = finding_for(
            statement=statement,
            ctx=ctx,
            rule_id=self.rule_id,
            severity="medium",
            decision="review",
            message=f"ALTER COLUMN TYPE rewrite behavior is unverified for PostgreSQL {ctx.pg_version}.",
            recommendation=(
                "Prefer an expand, batch-backfill, and cutover migration until the exact conversion is verified for the target version."
            ),
            confidence=0.65,
            evidence=(
                f"AST AlterTableCmd changes a column type; target PostgreSQL={ctx.pg_version}; "
                "rewrite behavior is not asserted."
            ),
            object_names=(table or "",),
        )
        return [finding] if finding is not None else []

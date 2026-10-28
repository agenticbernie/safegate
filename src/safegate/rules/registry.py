from __future__ import annotations

from safegate.rules.alter import (
    AddColumnDefaultRule,
    AlterColumnTypeRule,
    SetNotNullRule,
)
from safegate.rules.base import Rule
from safegate.rules.constraints import AddKeyConstraintRule, UnvalidatedConstraintRule
from safegate.rules.destructive import DestructiveStatementRule, RewriteOperationRule
from safegate.rules.index import (
    ConcurrentIndexTransactionRule,
    CreateIndexRule,
    DropIndexRule,
)

RULES: tuple[Rule, ...] = (
    CreateIndexRule(),
    DropIndexRule(),
    AddKeyConstraintRule(),
    AddColumnDefaultRule(),
    SetNotNullRule(),
    AlterColumnTypeRule(),
    UnvalidatedConstraintRule(),
    RewriteOperationRule(),
    DestructiveStatementRule(),
    ConcurrentIndexTransactionRule(),
)


def get_rules() -> tuple[Rule, ...]:
    return RULES

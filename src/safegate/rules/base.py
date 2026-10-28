from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, Protocol

if TYPE_CHECKING:
    from safegate.parser.postgres import ParsedStatement

Severity = Literal["low", "medium", "high"]
Decision = Literal["safe", "review", "block"]


@dataclass(frozen=True, slots=True)
class SourceLocation:
    file: str
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    decision: Decision
    message: str
    recommendation: str
    location: SourceLocation
    confidence: float
    evidence: str

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class AnalysisContext:
    pg_version: int = 16
    enabled_rules: Mapping[str, bool] = field(default_factory=dict)
    severity_overrides: Mapping[str, Severity] = field(default_factory=dict)
    allowlists: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def rule_enabled(self, rule_id: str) -> bool:
        return self.enabled_rules.get(rule_id, True)

    def severity_for(self, rule_id: str, default: Severity) -> Severity:
        return self.severity_overrides.get(rule_id, default)

    def is_allowlisted(self, rule_id: str, object_names: tuple[str, ...]) -> bool:
        configured = self.allowlists.get(rule_id, ())
        return any(name in configured for name in object_names if name)


class Rule(Protocol):
    rule_id: str

    def evaluate(
        self,
        statement: ParsedStatement,
        ctx: AnalysisContext,
    ) -> list[Finding]: ...


def qualified_name(node: object | None) -> str | None:
    if node is None:
        return None
    name = getattr(node, "relname", None)
    if not isinstance(name, str) or not name:
        return None
    schema = getattr(node, "schemaname", None)
    return f"{schema}.{name}" if isinstance(schema, str) and schema else name


def finding_for(
    *,
    statement: ParsedStatement,
    ctx: AnalysisContext,
    rule_id: str,
    severity: Severity,
    decision: Decision,
    message: str,
    recommendation: str,
    confidence: float,
    evidence: str,
    object_names: tuple[str, ...] = (),
) -> Finding | None:
    if ctx.is_allowlisted(rule_id, object_names):
        return None
    return Finding(
        rule_id=rule_id,
        severity=ctx.severity_for(rule_id, severity),
        decision=decision,
        message=message,
        recommendation=recommendation,
        location=statement.location,
        confidence=confidence,
        evidence=evidence,
    )

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pglast import parse_sql
from pglast.parser import ParseError, scan

from safegate.rules.base import Finding, SourceLocation

_COMMENT_TOKENS = {"SQL_COMMENT", "C_COMMENT"}


@dataclass(frozen=True, slots=True)
class ParsedStatement:
    statement: Any
    location: SourceLocation
    in_transaction: bool
    source: str


@dataclass(frozen=True, slots=True)
class ParseResult:
    statements: tuple[ParsedStatement, ...]
    findings: tuple[Finding, ...]
    error: str | None = None

    @property
    def has_error(self) -> bool:
        return self.error is not None


def _location(file: str, sql: str, offset: int) -> SourceLocation:
    bounded = min(max(offset, 0), len(sql))
    line = sql.count("\n", 0, bounded) + 1
    previous_newline = sql.rfind("\n", 0, bounded)
    column = bounded - previous_newline
    return SourceLocation(file=file, line=line, column=column)


def _error_offset(error: ParseError) -> int:
    marker = "at index "
    message = str(error)
    if marker not in message:
        return 0
    try:
        return int(message.rsplit(marker, maxsplit=1)[1])
    except ValueError:
        return 0


def _unknown_finding(file: str, sql: str, offset: int, evidence: str) -> Finding:
    location = _location(file, sql, offset)
    return Finding(
        rule_id="PARSER-001",
        severity="high",
        decision="review",
        message="PostgreSQL parser could not analyze this file.",
        recommendation="Fix or isolate the unsupported SQL, then run Safegate again.",
        location=location,
        confidence=1.0,
        evidence=evidence,
    )


def _statement_segments(sql: str) -> list[list[Any]]:
    segments: list[list[Any]] = []
    current: list[Any] = []
    for token in scan(sql):
        if token.name in _COMMENT_TOKENS:
            continue
        current.append(token)
        if token.name == "ASCII_59":
            if len(current) > 1:
                segments.append(current)
            current = []
    if current:
        segments.append(current)
    return segments


def parse_postgres(
    sql: str,
    *,
    file: str,
    transactional: bool = True,
) -> ParseResult:
    """Parse a complete SQL file and attach deterministic source locations.

    `transactional` represents migration-runner wrappers that do not appear in
    the SQL text. Explicit BEGIN/START and COMMIT/ROLLBACK are tracked as well.
    """
    try:
        raw_statements = parse_sql(sql)
        segments = _statement_segments(sql)
    except ParseError as error:
        offset = _error_offset(error)
        location = _location(file, sql, offset)
        evidence = f"Parser failed at line {location.line}, column {location.column}."
        finding = _unknown_finding(file, sql, offset, evidence)
        return ParseResult((), (finding,), error=str(error))

    if len(raw_statements) != len(segments):
        finding = _unknown_finding(
            file,
            sql,
            0,
            "AST statement count did not match PostgreSQL lexical statement spans.",
        )
        return ParseResult((), (finding,), error="statement/source mapping failed")

    parsed: list[ParsedStatement] = []
    explicit_transaction = False
    for raw, tokens in zip(raw_statements, segments, strict=True):
        ast_statement = raw.stmt
        kind = getattr(getattr(ast_statement, "kind", None), "name", "")
        if type(ast_statement).__name__ == "TransactionStmt" and kind in {
            "TRANS_STMT_BEGIN",
            "TRANS_STMT_START",
        }:
            explicit_transaction = True

        start = tokens[0].start
        end = tokens[-1].end + 1
        location = _location(file, sql, start)
        parsed.append(
            ParsedStatement(
                statement=ast_statement,
                location=location,
                in_transaction=transactional or explicit_transaction,
                source=sql[start:end],
            )
        )

        if type(ast_statement).__name__ == "TransactionStmt":
            has_savepoint = bool(getattr(ast_statement, "savepoint_name", None))
            chained = bool(getattr(ast_statement, "chain", False))
            if kind == "TRANS_STMT_PREPARE" or (
                kind in {"TRANS_STMT_COMMIT", "TRANS_STMT_ROLLBACK"}
                and not has_savepoint
                and not chained
            ):
                explicit_transaction = False

    return ParseResult(tuple(parsed), ())

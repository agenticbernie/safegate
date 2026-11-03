from __future__ import annotations

import glob
import os
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from safegate.config import SafegateConfig
from safegate.parser.postgres import parse_postgres
from safegate.rules.base import AnalysisContext, Finding, SourceLocation
from safegate.rules.pg16_behavior import analyze_statement
from safegate.rules.registry import get_rules
from safegate.rules.volatility_registry import Volatility, classify_default

ScanStatus = Literal["SAFE", "REVIEW", "BLOCK", "UNKNOWN"]


@dataclass(frozen=True, slots=True)
class ScanResult:
    file: str
    status: ScanStatus
    findings: tuple[Finding, ...]
    parser_error: bool = False


def _status(findings: Sequence[Finding]) -> ScanStatus:
    if any(finding.decision == "block" for finding in findings):
        return "BLOCK"
    if any(finding.decision == "review" for finding in findings):
        return "REVIEW"
    return "SAFE"


def scan_sql(
    sql: str,
    *,
    file: str,
    config: SafegateConfig | None = None,
) -> ScanResult:
    policy = config or SafegateConfig()
    input_path = Path(file)
    display_file = (
        relative_file(input_path, Path.cwd())
        if input_path.is_absolute()
        else input_path.as_posix()
    )
    parsed = parse_postgres(sql, file=display_file, transactional=policy.transactional)
    if parsed.has_error:
        return ScanResult(display_file, "UNKNOWN", parsed.findings, parser_error=True)

    enabled_rules = {
        rule_id: options.enabled for rule_id, options in policy.rules.items()
    }
    severity_overrides = {
        rule_id: options.severity
        for rule_id, options in policy.rules.items()
        if options.severity is not None
    }
    allowlists = {
        rule_id: options.allowlist
        for rule_id, options in policy.rules.items()
        if options.allowlist
    }
    context = AnalysisContext(
        pg_version=policy.pg_version,
        enabled_rules=enabled_rules,
        severity_overrides=severity_overrides,
        allowlists=allowlists,
    )

    findings: list[Finding] = []
    for parsed_statement in parsed.statements:
        for rule in get_rules():
            if context.rule_enabled(rule.rule_id):
                evaluated = rule.evaluate(parsed_statement, context)
                if evaluated:
                    impacts = analyze_statement(
                        parsed_statement.statement, pg_version=policy.pg_version
                    )
                    for finding in evaluated:
                        volatility: Volatility = "unknown"
                        if finding.rule_id == "SG-004":
                            expressions = [
                                getattr(constraint, "raw_expr", None)
                                for command in getattr(
                                    parsed_statement.statement, "cmds", ()
                                )
                                or ()
                                if getattr(
                                    getattr(command, "subtype", None), "name", ""
                                )
                                == "AT_AddColumn"
                                for constraint in (
                                    getattr(
                                        getattr(command, "def_", None),
                                        "constraints",
                                        None,
                                    )
                                    or ()
                                )
                                if getattr(
                                    getattr(constraint, "contype", None), "name", ""
                                )
                                == "CONSTR_DEFAULT"
                            ]
                            if len(expressions) == 1:
                                volatility = classify_default(
                                    expressions[0], pg_version=policy.pg_version
                                )
                        findings.append(
                            replace(
                                finding,
                                lock_impact=finding.lock_impact or impacts,
                                default_volatility=volatility,
                            )
                        )
    ordered = tuple(
        sorted(
            findings,
            key=lambda finding: (
                finding.location.file,
                finding.location.line,
                finding.location.column,
                finding.rule_id,
                finding.severity,
                finding.evidence,
            ),
        )
    )
    return ScanResult(display_file, _status(ordered), ordered)


def relative_file(path: Path, root: Path) -> str:
    resolved = path.resolve()
    root_resolved = root.resolve()
    try:
        return resolved.relative_to(root_resolved).as_posix()
    except ValueError:
        return Path(os.path.relpath(resolved, root_resolved)).as_posix()


def expand_sql_files(pattern: str, *, root: Path | None = None) -> tuple[Path, ...]:
    base = (root or Path.cwd()).resolve()
    candidate = Path(pattern)
    if not candidate.is_absolute():
        candidate = base / candidate

    if candidate.is_dir():
        paths = list(candidate.rglob("*.sql"))
    else:
        paths = [Path(item) for item in glob.glob(str(candidate), recursive=True)]
        if not paths and candidate.is_file():
            paths = [candidate]

    files = {
        path.resolve()
        for path in paths
        if path.is_file() and path.suffix.lower() == ".sql"
    }
    return tuple(sorted(files, key=lambda path: relative_file(path, base)))


def scan_file(path: Path, *, display_file: str, config: SafegateConfig) -> ScanResult:
    try:
        sql = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        location = SourceLocation(file=display_file, line=1, column=1)
        finding = Finding(
            rule_id="PARSER-002",
            severity="high",
            decision="review",
            message="Safegate could not read this SQL file as UTF-8.",
            recommendation="Check file permissions and encoding, then run Safegate again.",
            location=location,
            confidence=1.0,
            evidence=f"File read failed: {type(error).__name__}.",
        )
        return ScanResult(display_file, "UNKNOWN", (finding,), parser_error=True)
    return scan_sql(sql, file=display_file, config=config)

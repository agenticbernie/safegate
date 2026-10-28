from __future__ import annotations

import json
from collections.abc import Sequence
from io import StringIO
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from rich.console import Console

from safegate.rules.base import Finding
from safegate.scan import ScanResult, ScanStatus


class LocationReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    line: int = Field(ge=1)
    column: int = Field(ge=1)


class FindingReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    rule_id: str
    severity: Literal["low", "medium", "high"]
    decision: Literal["safe", "review", "block"]
    file: str
    location: LocationReport
    message: str
    recommendation: str
    evidence: str
    confidence: float = Field(ge=0.0, le=1.0)


class SummaryReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    safe: int = Field(ge=0)
    review: int = Field(ge=0)
    block: int = Field(ge=0)


class ScanReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    status: Literal["SAFE", "REVIEW", "BLOCK", "UNKNOWN"]
    summary: SummaryReport
    findings: tuple[FindingReport, ...]


def _report_finding(finding: Finding) -> FindingReport:
    return FindingReport(
        rule_id=finding.rule_id,
        severity=finding.severity,
        decision=finding.decision,
        file=finding.location.file,
        location=LocationReport(
            line=finding.location.line,
            column=finding.location.column,
        ),
        message=finding.message,
        recommendation=finding.recommendation,
        evidence=finding.evidence,
        confidence=finding.confidence,
    )


def build_report(results: Sequence[ScanResult]) -> ScanReport:
    if any(result.status == "UNKNOWN" for result in results):
        status: ScanStatus = "UNKNOWN"
    elif any(result.status == "BLOCK" for result in results):
        status = "BLOCK"
    elif any(result.status == "REVIEW" for result in results):
        status = "REVIEW"
    else:
        status = "SAFE"

    safe_count = sum(result.status == "SAFE" for result in results)
    review_count = sum(result.status in {"REVIEW", "UNKNOWN"} for result in results)
    block_count = sum(result.status == "BLOCK" for result in results)
    findings = sorted(
        (finding for result in results for finding in result.findings),
        key=lambda finding: (
            finding.location.file,
            finding.location.line,
            finding.location.column,
            finding.rule_id,
            finding.severity,
            finding.evidence,
        ),
    )
    return ScanReport(
        status=status,
        summary=SummaryReport(safe=safe_count, review=review_count, block=block_count),
        findings=tuple(_report_finding(finding) for finding in findings),
    )


def report_json(results: Sequence[ScanResult]) -> str:
    return (
        json.dumps(
            build_report(results).model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def report_text(results: Sequence[ScanResult]) -> str:
    report = build_report(results)
    icons = {
        "SAFE": "🟢",
        "REVIEW": "🟡",
        "BLOCK": "🔴",
        "UNKNOWN": "⚪",
    }
    output = StringIO()
    console = Console(file=output, force_terminal=False, color_system=None, width=100)
    console.print(f"{icons[report.status]} {report.status}")
    console.print(
        "Files: "
        f"{report.summary.safe} safe, {report.summary.review} review, "
        f"{report.summary.block} block"
    )
    for finding in report.findings:
        console.print(
            f"{finding.file}:{finding.location.line}:{finding.location.column} "
            f"[{finding.rule_id}] {finding.message}"
        )
        console.print(f"  Evidence: {finding.evidence}")
        console.print(f"  Recommendation: {finding.recommendation}")
    return output.getvalue()

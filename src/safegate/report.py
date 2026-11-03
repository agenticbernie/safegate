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


class LockImpactReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    relation: str | None
    required_mode: str | None
    plain_read_conflict: bool | None
    ordinary_write_conflict: bool | None
    runtime_contention: Literal["unknown"]
    rewrite: Literal["required", "not_required", "unknown"]
    evidence_confidence: Literal["verified", "conditional", "unknown"]
    assumptions: tuple[str, ...]


class EvidenceConfidenceReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    lock: Literal["verified", "conditional", "unknown"]
    rewrite: Literal["verified", "conditional", "unknown"]


class FindingReportV2(FindingReport):
    lock_impact: tuple[LockImpactReport, ...] | None
    context_hints_used: tuple[()] = ()
    evidence_confidence: EvidenceConfidenceReport
    default_volatility: Literal["immutable", "stable", "volatile", "unknown"]


class ScanReportV2(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: Literal["2.0"] = "2.0"
    status: Literal["SAFE", "REVIEW", "BLOCK", "UNKNOWN"]
    summary: SummaryReport
    findings: tuple[FindingReportV2, ...]


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


def _ordered_findings(results: Sequence[ScanResult]) -> list[Finding]:
    return sorted(
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
    findings = _ordered_findings(results)
    return ScanReport(
        status=status,
        summary=SummaryReport(safe=safe_count, review=review_count, block=block_count),
        findings=tuple(_report_finding(finding) for finding in findings),
    )


def build_report_v2(results: Sequence[ScanResult]) -> ScanReportV2:
    original = build_report(results)
    upgraded: list[FindingReportV2] = []
    for source, legacy in zip(
        _ordered_findings(results), original.findings, strict=True
    ):
        impacts = tuple(
            LockImpactReport(
                relation=impact.relation,
                required_mode=impact.required_mode,
                plain_read_conflict=impact.plain_read_conflict,
                ordinary_write_conflict=impact.ordinary_write_conflict,
                runtime_contention=impact.runtime_contention,
                rewrite=impact.rewrite,
                evidence_confidence=impact.evidence_confidence,
                assumptions=impact.assumptions,
            )
            for impact in source.lock_impact
        )
        confidence: Literal["verified", "conditional", "unknown"] = "verified"
        if not impacts or any(
            impact.evidence_confidence == "unknown" for impact in impacts
        ):
            confidence = "unknown"
        elif any(impact.evidence_confidence == "conditional" for impact in impacts):
            confidence = "conditional"
        upgraded.append(
            FindingReportV2(
                **legacy.model_dump(),
                lock_impact=impacts or None,
                evidence_confidence=EvidenceConfidenceReport(
                    lock=confidence, rewrite="unknown"
                ),
                default_volatility=source.default_volatility,
            )
        )
    return ScanReportV2(
        status=original.status, summary=original.summary, findings=tuple(upgraded)
    )


def report_json(
    results: Sequence[ScanResult], *, schema_version: Literal["1.0", "2.0"] = "1.0"
) -> str:
    report = (
        build_report(results) if schema_version == "1.0" else build_report_v2(results)
    )
    return (
        json.dumps(
            report.model_dump(mode="json"),
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

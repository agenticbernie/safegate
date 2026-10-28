from __future__ import annotations

from typing import Any

from safegate.github.client import GitHubClient

COMMENT_MARKER = "<!-- safegate-report-v1 -->"
_SEVERITY_ORDER = ("high", "medium", "low")


def _short_text(value: object, limit: int = 200) -> str:
    text = " ".join(str(value).split())
    if len(text) <= limit:
        return text
    return f"{text[: limit - 1]}…"


def build_comment_body(report: dict[str, Any]) -> str:
    status = report.get("status", "UNKNOWN")
    status_icons = {"SAFE": "🟢", "REVIEW": "🟡", "BLOCK": "🔴", "UNKNOWN": "⚪"}
    icon = status_icons.get(status, "⚪")
    summary = report.get("summary", {})
    findings = report.get("findings", [])
    if not isinstance(summary, dict) or not isinstance(findings, list):
        summary = {}
        findings = []
    summary_values = [summary.get(name, 0) for name in ("safe", "review", "block")]
    summary_values.append(len(findings))
    summary_row = "| " + " | ".join(str(value) for value in summary_values) + " |"

    lines = [
        f"## {icon} Safegate: {status}",
        "",
        "| Files SAFE | REVIEW | BLOCK | Findings |",
        "| ---: | ---: | ---: | ---: |",
        summary_row,
        "",
    ]

    for severity in _SEVERITY_ORDER:
        group = [
            finding
            for finding in findings
            if isinstance(finding, dict) and finding.get("severity") == severity
        ]
        if not group:
            continue
        lines.extend(
            [
                f"<details><summary>{severity.title()} severity ({len(group)})</summary>",
                "",
            ]
        )
        for finding in group:
            location = finding.get("location", {})
            if not isinstance(location, dict):
                location = {}
            file = _short_text(finding.get("file", "unknown"), 160)
            line = location.get("line", "?")
            column = location.get("column", "?")
            rule_id = _short_text(finding.get("rule_id", "UNKNOWN"), 32)
            message = _short_text(finding.get("message", ""), 200)
            recommendation = _short_text(finding.get("recommendation", ""), 200)
            evidence = _short_text(finding.get("evidence", ""), 200)
            lines.append(f"- **{rule_id}** `{file}:{line}:{column}`: {message}")
            if evidence:
                lines.append(f"  - Evidence: `{evidence}`")
            if recommendation:
                lines.append(f"  - Recommendation: {recommendation}")
        lines.extend(["", "</details>", ""])

    lines.append(COMMENT_MARKER)
    return "\n".join(lines).rstrip() + "\n"


def publish_report(
    report: dict[str, Any],
    *,
    token: str | None,
    repository: str,
    issue_number: int,
    head_sha: str,
    scan_exit_code: int,
) -> bool:
    if not token:
        return False
    if "/" not in repository:
        raise ValueError("GITHUB_REPOSITORY must be owner/repository")
    owner, repo_name = repository.split("/", maxsplit=1)
    client = GitHubClient(token)
    body = build_comment_body(report)
    client.create_or_update_comment(
        owner,
        repo_name,
        issue_number,
        body,
        marker=COMMENT_MARKER,
    )
    check_run = client.create_check_run(
        owner,
        repo_name,
        name="Safegate",
        head_sha=head_sha,
    )
    check_run_id = check_run.get("id")
    if isinstance(check_run_id, int):
        client.update_check_run(
            owner,
            repo_name,
            check_run_id,
            conclusion="success" if scan_exit_code == 0 else "failure",
            summary=(
                f"Safegate status: {report.get('status', 'UNKNOWN')}. "
                f"Findings: {len(report.get('findings', []))}."
            ),
        )
    return True

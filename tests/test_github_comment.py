from __future__ import annotations

import json
from io import BytesIO
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from safegate.github.client import GitHubApiError, GitHubClient
from safegate.github.comment import (
    COMMENT_MARKER,
    build_comment_body,
    publish_report,
)
from safegate.report import build_report


def _response(payload: object) -> BytesIO:
    return BytesIO(json.dumps(payload).encode("utf-8"))


def _report(scan_sql_fixture) -> dict[str, object]:
    return build_report([scan_sql_fixture("review/add_column_default.sql")]).model_dump(
        mode="json"
    )


def test_create_new_comment_when_marker_is_absent() -> None:
    client = GitHubClient("secret-token")
    with patch(
        "urllib.request.urlopen",
        side_effect=[_response([]), _response({"id": 15, "body": "new"})],
    ) as open_url:
        result = client.create_or_update_comment(
            "owner", "repo", 7, f"report\n{COMMENT_MARKER}", marker=COMMENT_MARKER
        )

    assert result["id"] == 15
    assert [call.args[0].get_method() for call in open_url.call_args_list] == [
        "GET",
        "POST",
    ]
    assert "secret-token" not in repr(open_url.call_args_list)


def test_update_existing_comment_when_marker_is_present() -> None:
    client = GitHubClient("secret-token")
    existing = {"id": 21, "body": f"old report\n{COMMENT_MARKER}"}
    with patch(
        "urllib.request.urlopen",
        side_effect=[_response([existing]), _response({"id": 21, "body": "new"})],
    ) as open_url:
        result = client.create_or_update_comment(
            "owner", "repo", 7, f"updated\n{COMMENT_MARKER}", marker=COMMENT_MARKER
        )

    assert result["id"] == 21
    assert [call.args[0].get_method() for call in open_url.call_args_list] == [
        "GET",
        "PATCH",
    ]
    assert "/issues/comments/21" in open_url.call_args_list[1].args[0].full_url


def test_second_run_updates_instead_of_creating_another_comment(
    scan_sql_fixture,
) -> None:
    client = GitHubClient("secret-token")
    created = {"id": 21, "body": f"first report\n{COMMENT_MARKER}"}
    responses = [
        _response([]),
        _response(created),
        _response([created]),
        _response({"id": 21, "body": "updated"}),
    ]
    report = _report(scan_sql_fixture)
    with patch("urllib.request.urlopen", side_effect=responses) as open_url:
        first = build_comment_body(report)
        client.create_or_update_comment(
            "owner", "repo", 7, first, marker=COMMENT_MARKER
        )
        second = build_comment_body(report)
        client.create_or_update_comment(
            "owner", "repo", 7, second, marker=COMMENT_MARKER
        )

    methods = [call.args[0].get_method() for call in open_url.call_args_list]
    assert methods.count("POST") == 1
    assert methods.count("PATCH") == 1


def test_missing_token_skips_github_reporting_without_crashing(
    scan_sql_fixture,
) -> None:
    with patch("urllib.request.urlopen") as open_url:
        result = publish_report(
            _report(scan_sql_fixture),
            token="",
            repository="owner/repo",
            issue_number=7,
            head_sha="abc123",
            scan_exit_code=0,
        )

    assert result is False
    open_url.assert_not_called()


def test_publish_report_creates_comment_and_completes_check_run(
    scan_sql_fixture,
) -> None:
    responses = [
        _response([]),
        _response({"id": 15}),
        _response({"id": 29}),
        _response({"id": 29, "status": "completed"}),
    ]
    with patch("urllib.request.urlopen", side_effect=responses) as open_url:
        published = publish_report(
            _report(scan_sql_fixture),
            token="secret-token",
            repository="owner/repo",
            issue_number=7,
            head_sha="abc123",
            scan_exit_code=1,
        )

    assert published is True
    requests = [call.args[0] for call in open_url.call_args_list]
    assert [request.get_method() for request in requests] == [
        "GET",
        "POST",
        "POST",
        "PATCH",
    ]
    assert requests[2].full_url.endswith("/repos/owner/repo/check-runs")
    assert requests[3].full_url.endswith("/repos/owner/repo/check-runs/29")
    check_update = json.loads(requests[3].data)
    assert check_update["conclusion"] == "failure"


def test_comment_groups_findings_and_truncates_evidence(scan_sql_fixture) -> None:
    report = _report(scan_sql_fixture)
    finding = report["findings"][0]
    assert isinstance(finding, dict)
    finding["evidence"] = "x" * 250

    body = build_comment_body(report)

    assert COMMENT_MARKER in body
    assert "Medium severity" in body
    assert "x" * 201 not in body
    assert "x" * 199 + "…" in body


def test_client_retries_two_times_on_server_error() -> None:
    client = GitHubClient("secret-token")
    server_error = HTTPError(
        "https://api.github.com/test",
        503,
        "temporary failure",
        hdrs=None,
        fp=BytesIO(b"private response"),
    )
    with patch(
        "urllib.request.urlopen",
        side_effect=[server_error, server_error, _response({"ok": True})],
    ) as open_url:
        result = client._request("GET", "/test")

    assert result == {"ok": True}
    assert open_url.call_count == 3
    assert all(call.kwargs["timeout"] == 10.0 for call in open_url.call_args_list)


def test_client_does_not_expose_response_body_on_client_error() -> None:
    client = GitHubClient("secret-token")
    denied = HTTPError(
        "https://api.github.com/test",
        403,
        "denied",
        hdrs=None,
        fp=BytesIO(b"body contains secret SQL"),
    )
    with (
        patch("urllib.request.urlopen", side_effect=denied),
        pytest.raises(GitHubApiError, match="HTTP 403") as error,
    ):
        client._request("GET", "/test")

    assert "secret SQL" not in str(error.value)
    assert "secret-token" not in str(error.value)


def test_client_sanitizes_timeout_error() -> None:
    client = GitHubClient("secret-token")
    with (
        patch("urllib.request.urlopen", side_effect=TimeoutError("private detail")),
        pytest.raises(GitHubApiError, match="network error") as error,
    ):
        client._request("GET", "/test")

    assert "private detail" not in str(error.value)
    assert "secret-token" not in str(error.value)

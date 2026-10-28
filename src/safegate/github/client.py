from __future__ import annotations

import json
import urllib.request
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote


class GitHubApiError(RuntimeError):
    """A sanitized GitHub API failure without response bodies or credentials."""


class GitHubClient:
    def __init__(
        self,
        token: str,
        *,
        api_url: str = "https://api.github.com",
        timeout: float = 10.0,
        retries: int = 2,
    ) -> None:
        if not token:
            raise ValueError("GitHub token is required")
        self._token = token
        self._api_url = api_url.rstrip("/")
        self._timeout = timeout
        self._retries = retries

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            f"{self._api_url}{path}",
            data=body,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Content-Type": "application/json"} if body is not None else {}),
            },
            method=method,
        )
        for attempt in range(self._retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self._timeout) as response:
                    raw_response = response.read()
                if not raw_response:
                    return {}
                try:
                    return json.loads(raw_response)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise GitHubApiError(
                        "GitHub API returned an invalid JSON response."
                    ) from None
            except HTTPError as error:
                if 500 <= error.code <= 599 and attempt < self._retries:
                    continue
                raise GitHubApiError(
                    f"GitHub API returned HTTP {error.code}."
                ) from None
            except (TimeoutError, URLError, OSError):
                raise GitHubApiError(
                    "GitHub API request failed due to a network error."
                ) from None
        raise GitHubApiError("GitHub API request failed after retries.")

    def create_or_update_comment(
        self,
        owner: str,
        repository: str,
        issue_number: int,
        body: str,
        *,
        marker: str,
    ) -> dict[str, Any]:
        repo_path = self._repo_path(owner, repository)
        page = 1
        existing_comment: dict[str, Any] | None = None
        while True:
            comments = self._request(
                "GET",
                f"{repo_path}/issues/{issue_number}/comments?per_page=100&page={page}",
            )
            if not isinstance(comments, list):
                raise GitHubApiError("GitHub API returned an invalid comments list.")
            existing_comment = next(
                (
                    comment
                    for comment in comments
                    if isinstance(comment, dict)
                    and isinstance(comment.get("body"), str)
                    and marker in comment["body"]
                ),
                None,
            )
            if existing_comment is not None or len(comments) < 100:
                break
            page += 1

        if existing_comment is not None:
            comment_id = existing_comment.get("id")
            if not isinstance(comment_id, int):
                raise GitHubApiError("Existing Safegate comment has no valid id.")
            return self._request(
                "PATCH",
                f"{repo_path}/issues/comments/{comment_id}",
                {"body": body},
            )
        return self._request(
            "POST",
            f"{repo_path}/issues/{issue_number}/comments",
            {"body": body},
        )

    def create_check_run(
        self,
        owner: str,
        repository: str,
        *,
        name: str,
        head_sha: str,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"{self._repo_path(owner, repository)}/check-runs",
            {"name": name, "head_sha": head_sha, "status": "in_progress"},
        )

    def update_check_run(
        self,
        owner: str,
        repository: str,
        check_run_id: int,
        *,
        conclusion: str,
        summary: str,
    ) -> dict[str, Any]:
        return self._request(
            "PATCH",
            f"{self._repo_path(owner, repository)}/check-runs/{check_run_id}",
            {
                "status": "completed",
                "conclusion": conclusion,
                "output": {"title": "Safegate migration scan", "summary": summary},
            },
        )

    @staticmethod
    def _repo_path(owner: str, repository: str) -> str:
        return f"/repos/{quote(owner, safe='')}/{quote(repository, safe='')}"

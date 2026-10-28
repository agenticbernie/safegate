# Safegate

Static PostgreSQL migration checks using the PostgreSQL 16 grammar.

## Local CLI

```sh
uv run safegate scan "db/migrations/**/*.sql" --format text
```

Build and run the local image without network access during the scan:

```sh
docker build -t safegate .
docker run --rm --network=none \
  -v "$PWD/db/migrations:/sql:ro" \
  safegate "/sql/**/*.sql"
```

The local `Dockerfile` runs as the non-root `safegate` user.

## GitHub Action

```yaml
- uses: OWNER/REPOSITORY@REF
  with:
    files: db/migrations/**/*.sql
    fail-on: block
    pg-version: '16'
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

The Action uses `Dockerfile.action`. GitHub Docker Actions run as root to access
the mounted workspace and command files such as `GITHUB_OUTPUT`; see [GitHub's
Dockerfile guidance](https://docs.github.com/en/actions/reference/workflows-and-actions/dockerfile-support).
The Action entrypoint checks these paths before scanning. The scan subprocess
imports no HTTP client and makes no network calls. GitHub API reporting runs only
after the scan, for pull requests when a token is provided.

# Safegate

Privacy-first static analysis safety gate for PostgreSQL migrations.

[![Version](https://img.shields.io/badge/version-v0.1.0-blue)](https://github.com/agenticbernie/safegate/releases/tag/v0.1.0)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Coverage: 86%+](https://img.shields.io/badge/coverage-86%25%2B-brightgreen)
![PostgreSQL 16](https://img.shields.io/badge/PostgreSQL-16-336791)

A normal `CREATE INDEX` can block writes, and an unbounded `UPDATE` can touch every row. Safegate parses migration SQL before merge and reports `SAFE`, `REVIEW`, `BLOCK`, or `UNKNOWN` with a rule, source location, evidence, and recommendation.

## Features

- **AST parsing:** Powered by `pglast` AST, not brittle regex. The parser uses PostgreSQL 16 grammar; `--pg-version` sets the target version used by version-sensitive rules.
- **Private by default:** **Your SQL and schema NEVER leave your machine or CI runner.** The scanner has no network calls or telemetry. When GitHub reporting is enabled, the Action sends finding metadata (status, rule, file/line, evidence, and recommendation) to GitHub for the PR comment and check. It does not upload source SQL or schema.
- **10 migration risk rules:** SG-001 through SG-010 cover indexes, constraints, table rewrites, destructive DDL/DML, and transaction boundaries. Findings are risk signals, not a guarantee that a migration is safe; version-dependent or unknown behavior remains `REVIEW` or `UNKNOWN`.
- **Repeatable output:** Versioned JSON reports with deterministic ordering, plus idempotent GitHub PR comments and check runs.
- **Three run modes:** Python CLI, GitHub Action, or Docker. The local Docker image runs as non-root and scans with networking disabled.

## Quick start

### CLI

Requires Python 3.12.

```sh
uv pip install safegate
safegate scan "db/migrations/**/*.sql" --format text
```

By default, `--fail-on block` exits `1` for a `BLOCK` result. Use `--fail-on review` to fail on either `REVIEW` or `BLOCK`, or `--fail-on never` to report without failing on findings. Parser and tool errors return exit code `2` regardless of this setting.

```sh
safegate scan "db/migrations/**/*.sql" --format json --pg-version 16 --fail-on review
safegate doctor
```

### GitHub Action

Add this workflow as `.github/workflows/safegate.yml`:

```yaml
name: Safegate Migration Check
on: [pull_request]
jobs:
  check-migrations:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      checks: write
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      - name: Run Safegate
        uses: agenticbernie/safegate@v0.1.0
        with:
          files: db/migrations/**/*.sql
          fail-on: block
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

The Action runs the scan in its container, then uses `GITHUB_TOKEN` to create or update one PR comment and a check run. GitHub reporting is skipped without a token or outside a `pull_request` event; the scan and Action outputs still run.

### Docker, offline scan

Build the local CLI image, then scan a read-only migration mount with network access disabled:

```sh
docker build -t safegate .
docker run --rm --network=none \
  -v "$PWD/db/migrations:/sql:ro" \
  safegate "/sql/**/*.sql"
```

`Dockerfile` runs as the non-root `safegate` user. `Dockerfile.action` is a separate image for GitHub's mounted workspace and `GITHUB_OUTPUT` file; it runs as root because GitHub controls those mount permissions. Both images scan SQL locally, and neither needs network access during the scan.

## Rules

| ID | Rule | Default decision | Description |
| --- | --- | --- | --- |
| SG-001 | `CREATE INDEX` without `CONCURRENTLY` | BLOCK | Index creation may block writes. |
| SG-002 | `DROP INDEX` without `CONCURRENTLY` | BLOCK | Index removal may block writes. |
| SG-003 | Add primary key or unique constraint | BLOCK | `ALTER TABLE` builds a supporting index. |
| SG-004 | Add column with a default | REVIEW | Fast-path behavior depends on PostgreSQL version. |
| SG-005 | Set or add `NOT NULL` | REVIEW | Existing rows may need validation. |
| SG-006 | Change a column type | REVIEW | Conversion may rewrite a table or indexes. |
| SG-007 | Add `CHECK` or foreign key without `NOT VALID` | REVIEW | Constraint validation can scan existing rows. |
| SG-008 | `VACUUM FULL`, `CLUSTER`, or `REINDEX` | BLOCK / REVIEW | Decision depends on operation and options. |
| SG-009 | Destructive DDL or unbounded DML | BLOCK / REVIEW | Unscoped changes can affect all rows. |
| SG-010 | Concurrent index inside a transaction | BLOCK | `CONCURRENTLY` cannot run in a transaction block. |

`WHERE FALSE` updates and deletes are treated as no-ops. A predicate that cannot be proven safe is reviewed rather than assumed safe. By default, Safegate conservatively treats each migration file as transactional for SG-010; configure `transactional = false` only when your migration runner executes files outside transactions.

## Configuration

Safegate reads `.safegate.toml` from the current directory by default. Set `pg_version`, transaction behavior, and per-rule enablement, severity, or object allowlists. Unknown configuration keys are errors.

```toml
pg_version = 16
transactional = true

[rules."SG-001"]
enabled = true
severity = "medium"
allowlist = ["public.events"]
```

Pass another policy with `--config path/to/policy.toml`. The CLI `--pg-version` option overrides the policy's `pg_version`; the parser still uses PostgreSQL 16 grammar.

## Release and roadmap

- [Safegate v0.1.0 release notes](https://github.com/agenticbernie/safegate/releases/tag/v0.1.0)
- v0.2.0 goals: optional read-only runtime metadata and opt-in, local AI suggestions. Neither feature is part of v0.1.0.

## Contributing

Use Python 3.12 and `uv` to reproduce the development environment and run the checks:

```sh
uv sync --locked --all-groups
uv run pytest --cov=src/safegate --cov-report=term-missing
uv run ruff check .
uv run ruff format --check .
uv run mypy src
```

This project is licensed under the [MIT License](LICENSE).

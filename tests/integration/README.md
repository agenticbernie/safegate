# PostgreSQL 16 integration oracle

These tests run PostgreSQL **only as a disposable test fixture**. SafeGate itself never opens a database connection. The image is Docker's official PostgreSQL 16.15 Alpine multi-platform index, tested on `linux/amd64`:

```text
postgres:16.15-alpine@sha256:0cefaabd882e42bcb2a2f3dc56d3ce4770560ba62fd7f197f1a2e008fd5731ab
```

Prepare images before disconnecting the test environment:

```sh
docker pull --platform=linux/amd64 postgres:16.15-alpine@sha256:0cefaabd882e42bcb2a2f3dc56d3ce4770560ba62fd7f197f1a2e008fd5731ab
docker build -t safegate-pg16-oracle-cli:latest .
uv sync --locked --all-groups
SAFEGATE_PG16_REQUIRED=1 uv run pytest tests/integration/
```

CI performs preparation while online, then runs the suite from a prebuilt runner with `--pull=never --network=none`. All PostgreSQL and scanner containers also use `--pull=never --network=none`. PostgreSQL has `listen_addresses=''`, no published ports, and local trust authentication inside its private container; each test receives a fresh database. `psql` runs via `docker exec` and the private Unix socket. The fixture removes the database and container, including anonymous volumes, in `finally` blocks.

`SAFEGATE_PG16_REQUIRED=1` makes missing Docker or either uncached image a test failure. Without it, a local full suite skips tests whose image is unavailable. The dedicated CI job always sets it. Set `SAFEGATE_TEST_CLI_IMAGE` only to the prebuilt scanner image being tested. No tests pull or build an image.

Lock tests check the relation OID, holder and waiter PIDs, granted mode, and `pg_blocking_pids`, then release the transaction and verify the waiting statement completes. Watchdogs fail with lock or process diagnostics rather than judging blocking from time alone. Rewrite tests compare table OID, tablespace, path, and heap filenode, while treating indexes and partition leaves separately. A tablespace move is a negative control. The offline scanner test uses a separate networkless container with no database socket and an audited Python socket guard; it compares the JSON report with an equivalent local scan and verifies the guard rejects an intentional socket attempt.

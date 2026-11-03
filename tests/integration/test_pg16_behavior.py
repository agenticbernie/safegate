"""PostgreSQL 16 oracle; all database sessions are in a networkless container."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

import pytest

from safegate.rules.conversion_matrix import ColumnType, classify_conversion
from safegate.scan import scan_sql

from . import conftest as harness
from .conftest import CLI_IMAGE, Database, Session, docker, require_image


def test_readiness_waits_for_initialization_server_to_stop(monkeypatch) -> None:
    calls: list[str] = []
    log_count = 0
    ready_count = 0

    def fake_docker(*args: str, **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal log_count, ready_count
        calls.append(args[0])
        if args[0] == "logs":
            log_count += 1
            output = (
                "temporary server accepts connections"
                if log_count == 1
                else "PostgreSQL init process complete; ready for start up."
            )
            return subprocess.CompletedProcess(args, 0, output, "")
        ready_count += 1
        return subprocess.CompletedProcess(args, 1 if ready_count == 1 else 0, "", "")

    monkeypatch.setattr(harness, "docker", fake_docker)
    monkeypatch.setattr(harness.time, "sleep", lambda _: None)
    harness.wait_for_postgres("fixture")
    assert calls == ["logs", "logs", "exec", "logs", "exec"]


def wait_for_lock(
    observer: Session, holder: int, waiter: int, oid: int, mode: str
) -> None:
    deadline = time.monotonic() + 15
    last = ""
    while time.monotonic() < deadline:
        last = observer.query(
            f"SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='relation' AND pid={waiter} "
            f"AND relation={oid} AND mode='{mode}' AND NOT granted) "
            f"AND {holder}=ANY(pg_blocking_pids({waiter}))"
        )
        if last == "t":
            return
        time.sleep(0.1)
    diagnostics = observer.query(
        f"SELECT pid, relation, mode, granted FROM pg_locks WHERE pid IN ({holder}, {waiter}) ORDER BY pid, mode"
    )
    raise AssertionError(
        f"Lock barrier timed out; expected waiter={waiter} mode={mode} oid={oid}, holder={holder}, last={last!r}; locks:\n{diagnostics}"
    )


def assert_granted(observer: Session, pid: int, oid: int, mode: str) -> None:
    assert (
        observer.query(
            f"SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='relation' AND pid={pid} AND relation={oid} AND mode='{mode}' AND granted)"
        )
        == "t"
    )


def snapshot(session: Session, relation: str) -> tuple[str, str, str, str]:
    row = session.query(
        "SELECT c.oid, pg_relation_filenode(c.oid), "
        "coalesce(nullif(c.reltablespace, 0), d.dattablespace), pg_relation_filepath(c.oid) "
        "FROM pg_class c CROSS JOIN pg_database d "
        f"WHERE c.oid='{relation}'::regclass AND d.datname=current_database()"
    )
    fields = row.split("|")
    assert len(fields) == 4 and all(fields), row
    return fields[0], fields[1], fields[2], fields[3]


def assert_rewrite(
    before: tuple[str, str, str, str], after: tuple[str, str, str, str], expected: bool
) -> None:
    assert before[0] == after[0], "table OID changed"
    assert before[2] == after[2], "tablespace changed during rewrite test"
    assert (before[1] != after[1]) is expected, (before, after)


def test_create_index_holds_share_lock_and_blocks_insert(pg_db: Database) -> None:
    holder, waiter, observer = pg_db.session(), pg_db.session(), pg_db.session()
    observer.query("CREATE TABLE t(id integer); INSERT INTO t VALUES (1)")
    oid = int(observer.query("SELECT 't'::regclass::oid"))
    holder.query("BEGIN; CREATE INDEX t_idx ON t(id)")
    assert_granted(observer, holder.pid, oid, "ShareLock")
    marker = waiter.start("INSERT INTO t VALUES (2)")
    wait_for_lock(observer, holder.pid, waiter.pid, oid, "RowExclusiveLock")
    assert observer.query("SELECT count(*) FROM t") == "1"
    finding = scan_sql("CREATE INDEX t_idx ON t(id)", file="x.sql").findings[0]
    assert finding.lock_impact[0].required_mode == "SHARE"
    assert finding.lock_impact[0].ordinary_write_conflict is True
    holder.query("COMMIT")
    waiter.wait(marker)
    assert observer.query("SELECT count(*) FROM t") == "2"


def test_drop_index_holds_access_exclusive_and_blocks_select(pg_db: Database) -> None:
    holder, waiter, observer = pg_db.session(), pg_db.session(), pg_db.session()
    observer.query(
        "CREATE TABLE t(id integer); CREATE INDEX t_idx ON t(id); INSERT INTO t VALUES (1)"
    )
    oid = int(observer.query("SELECT 't'::regclass::oid"))
    holder.query("BEGIN; DROP INDEX t_idx")
    assert_granted(observer, holder.pid, oid, "AccessExclusiveLock")
    marker = waiter.start("SELECT count(*) FROM t")
    wait_for_lock(observer, holder.pid, waiter.pid, oid, "AccessShareLock")
    finding = scan_sql("DROP INDEX t_idx", file="x.sql").findings[0]
    assert finding.lock_impact[0].plain_read_conflict is True
    holder.query("COMMIT")
    assert waiter.wait(marker) == "1"


def test_volatile_default_rewrites_heap(pg_db: Database) -> None:
    session = pg_db.session()
    session.query(
        "CREATE TABLE t(id integer); INSERT INTO t SELECT generate_series(1, 5)"
    )
    before = snapshot(session, "t")
    session.query(
        "ALTER TABLE t ADD COLUMN ts timestamptz DEFAULT pg_catalog.clock_timestamp()"
    )
    assert_rewrite(before, snapshot(session, "t"), True)
    assert session.query("SELECT count(*) FROM t WHERE ts IS NOT NULL") == "5"
    finding = scan_sql(
        "ALTER TABLE t ADD COLUMN ts timestamptz DEFAULT pg_catalog.clock_timestamp()",
        file="x.sql",
    ).findings[0]
    assert finding.default_volatility == "volatile"
    assert finding.lock_impact[0].rewrite == "unknown"


@pytest.mark.parametrize(
    ("column", "default", "expected"),
    [("integer", "42", "42"), ("timestamptz", "pg_catalog.now()", "t")],
)
def test_nonvolatile_default_preserves_filenode_but_locks_table(
    pg_db: Database, column: str, default: str, expected: str
) -> None:
    holder, observer = pg_db.session(), pg_db.session()
    observer.query(
        "CREATE TABLE t(id integer); INSERT INTO t SELECT generate_series(1, 5)"
    )
    before = snapshot(observer, "t")
    holder.query(f"BEGIN; ALTER TABLE t ADD COLUMN value {column} DEFAULT {default}")
    assert_granted(observer, holder.pid, int(before[0]), "AccessExclusiveLock")
    holder.query("COMMIT")
    assert_rewrite(before, snapshot(observer, "t"), False)
    value_query = (
        "SELECT min(value) FROM t"
        if column == "integer"
        else "SELECT bool_and(value IS NOT NULL) FROM t"
    )
    assert observer.query(value_query) == expected


@pytest.mark.parametrize(
    ("old_sql", "new_sql", "value", "old", "new", "rewrite"),
    [
        (
            "varchar(10)",
            "varchar(20)",
            "'abc'",
            ColumnType("varchar", 10),
            ColumnType("varchar", 20),
            False,
        ),
        (
            "varchar(10)",
            "varchar",
            "'abc'",
            ColumnType("varchar", 10),
            ColumnType("varchar", None),
            False,
        ),
        (
            "varchar(20)",
            "varchar(10)",
            "'abc'",
            ColumnType("varchar", 20),
            ColumnType("varchar", 10),
            True,
        ),
        (
            "varchar",
            "varchar(10)",
            "'abc'",
            ColumnType("varchar", None),
            ColumnType("varchar", 10),
            True,
        ),
        (
            "integer",
            "bigint",
            "123",
            ColumnType("integer", None),
            ColumnType("bigint", None),
            True,
        ),
        (
            "text",
            "varchar",
            "'abc'",
            ColumnType("text", None),
            ColumnType("varchar", None),
            False,
        ),
        (
            "varchar",
            "text",
            "'abc'",
            ColumnType("varchar", None),
            ColumnType("text", None),
            False,
        ),
    ],
)
def test_type_conversions_match_heap_filenode(
    pg_db: Database,
    old_sql: str,
    new_sql: str,
    value: str,
    old: ColumnType,
    new: ColumnType,
    rewrite: bool,
) -> None:
    session = pg_db.session()
    session.query(
        f"CREATE TABLE t(id int, v {old_sql}); INSERT INTO t VALUES (1, {value}); CREATE INDEX t_idx ON t(v)"
    )
    before, old_index = snapshot(session, "t"), snapshot(session, "t_idx")
    session.query(f"ALTER TABLE t ALTER COLUMN v TYPE {new_sql}")
    after, new_index = snapshot(session, "t"), snapshot(session, "t_idx")
    assert_rewrite(before, after, rewrite)
    # PostgreSQL may replace an index (including its OID) independently of the heap.
    assert old_index[1] and new_index[1]
    assert session.query("SELECT v::text FROM t") == value.strip("'")
    assert classify_conversion(old, new, pg_version=16, identity_using=True) == (
        "required" if rewrite else "not_required"
    )
    finding = scan_sql(
        f"ALTER TABLE t ALTER COLUMN v TYPE {new_sql}", file="x.sql"
    ).findings[0]
    assert finding.lock_impact[0].rewrite == "unknown"


def test_nonidentity_using_forces_rewrite(pg_db: Database) -> None:
    session = pg_db.session()
    session.query("CREATE TABLE t(v varchar(10)); INSERT INTO t VALUES ('abc')")
    before = snapshot(session, "t")
    session.query("ALTER TABLE t ALTER COLUMN v TYPE varchar(20) USING upper(v)")
    assert_rewrite(before, snapshot(session, "t"), True)
    assert session.query("SELECT v FROM t") == "ABC"
    assert (
        classify_conversion(
            ColumnType("varchar", 10),
            ColumnType("varchar", 20),
            pg_version=16,
            identity_using=False,
        )
        == "unknown"
    )


def test_identity_using_allows_widening_without_rewrite(pg_db: Database) -> None:
    session = pg_db.session()
    session.query("CREATE TABLE t(v varchar(10)); INSERT INTO t VALUES ('abc')")
    before = snapshot(session, "t")
    session.query("ALTER TABLE t ALTER COLUMN v TYPE varchar(20) USING v")
    assert_rewrite(before, snapshot(session, "t"), False)
    assert session.query("SELECT v FROM t") == "abc"


def test_narrowing_overlength_fails_without_committing_rewrite(pg_db: Database) -> None:
    session = pg_db.session()
    session.query(
        "CREATE TABLE t(v varchar(20)); INSERT INTO t VALUES ('abcdefghijkl')"
    )
    before = snapshot(session, "t")
    failed = docker(
        "exec",
        pg_db.container,
        "psql",
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
        "-h",
        "/var/run/postgresql",
        "-U",
        "postgres",
        "-d",
        pg_db.name,
        "-c",
        "ALTER TABLE t ALTER COLUMN v TYPE varchar(5)",
        check=False,
    )
    assert failed.returncode != 0 and "too long" in failed.stderr
    assert_rewrite(before, snapshot(session, "t"), False)
    assert session.query("SELECT v FROM t") == "abcdefghijkl"


def test_partitioned_parent_has_no_heap_and_leaves_track_rewrites(
    pg_db: Database,
) -> None:
    session = pg_db.session()
    session.query(
        "CREATE TABLE p(id integer, v varchar(10)) PARTITION BY RANGE(id); CREATE TABLE p1 PARTITION OF p FOR VALUES FROM (0) TO (10); CREATE TABLE p2 PARTITION OF p FOR VALUES FROM (10) TO (20); INSERT INTO p VALUES (1, 'abc'), (11, 'def')"
    )
    assert session.query("SELECT pg_relation_filenode('p'::regclass) IS NULL") == "t"
    before = [snapshot(session, name) for name in ("p1", "p2")]
    session.query("ALTER TABLE p ALTER COLUMN v TYPE varchar(20)")
    middle = [snapshot(session, name) for name in ("p1", "p2")]
    for old, new in zip(before, middle, strict=True):
        assert_rewrite(old, new, False)
    session.query("ALTER TABLE p ALTER COLUMN v TYPE varchar(5)")
    for old, name in zip(middle, ("p1", "p2"), strict=True):
        assert_rewrite(old, snapshot(session, name), True)
    assert session.query("SELECT count(*) FROM p") == "2"


def test_tablespace_move_is_not_evidence_of_alter_type_rewrite(pg_db: Database) -> None:
    session = pg_db.session()
    session.query("CREATE TABLE t(id int); INSERT INTO t VALUES (1)")
    before = snapshot(session, "t")
    location = f"/tmp/sg_ts_{uuid4().hex}"
    docker("exec", pg_db.container, "mkdir", location)
    docker("exec", pg_db.container, "chown", "postgres:postgres", location)
    try:
        session.query(f"CREATE TABLESPACE oracle_ts LOCATION '{location}'")
        session.query("ALTER TABLE t SET TABLESPACE oracle_ts")
        after = snapshot(session, "t")
        assert before[0] == after[0] and before[2] != after[2] and before[3] != after[3]
        assert session.query("SELECT id FROM t") == "1"
    finally:
        session.query("ALTER TABLE t SET TABLESPACE pg_default")
        session.query("DROP TABLESPACE IF EXISTS oracle_ts")


@pytest.mark.parametrize(
    "sql", ["CREATE INDEX CONCURRENTLY idx ON t(id)", "DROP INDEX CONCURRENTLY idx"]
)
def test_concurrent_index_commands_reject_transaction_blocks(
    pg_db: Database, sql: str
) -> None:
    session = pg_db.session()
    session.query("CREATE TABLE t(id integer); CREATE INDEX idx ON t(id)")
    result = docker(
        "exec",
        pg_db.container,
        "psql",
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
        "-h",
        "/var/run/postgresql",
        "-U",
        "postgres",
        "-d",
        pg_db.name,
        "-c",
        f"BEGIN; {sql}; COMMIT",
        check=False,
    )
    assert (
        result.returncode != 0
        and "cannot run inside a transaction block" in result.stderr
    )
    assert scan_sql(f"BEGIN; {sql}; COMMIT", file="x.sql").status == "BLOCK"


def test_offline_cli_preserves_static_findings_without_socket_attempts(
    tmp_path: Path,
) -> None:
    require_image(CLI_IMAGE)
    tmp_path.chmod(0o755)
    (tmp_path / "guard").mkdir(mode=0o755)
    (tmp_path / "guard" / "sitecustomize.py").write_text(
        "import os, sys\n"
        "def deny(event, args):\n"
        "    if event.startswith('socket.'):\n"
        "        print('SAFEGATE_SOCKET_ATTEMPT', file=sys.stderr, flush=True)\n"
        "        os._exit(91)\n"
        "sys.addaudithook(deny)\n"
        "print('SAFEGATE_SOCKET_GUARD_ACTIVE', file=sys.stderr, flush=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "migration.sql").write_text(
        "CREATE INDEX i ON public.t(id); DROP INDEX i; "
        "ALTER TABLE t ADD CONSTRAINT u UNIQUE (id); "
        "ALTER TABLE t ADD COLUMN x int DEFAULT 42; "
        "ALTER TABLE t ALTER COLUMN id TYPE bigint; DELETE FROM t;",
        encoding="utf-8",
    )
    options = [
        "migration.sql",
        "--format",
        "json",
        "--report-schema",
        "2.0",
        "--fail-on",
        "never",
    ]
    env = dict(os.environ, PYTHONPATH=str(tmp_path / "guard"))
    local = subprocess.run(
        [sys.executable, "-m", "safegate", "scan", *options],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    command = [
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--volume",
        f"{tmp_path}:/scan:ro",
        "--workdir",
        "/scan",
        "--env",
        "PYTHONPATH=/scan/guard",
    ]
    offline = docker(*command, CLI_IMAGE, *options)
    assert (
        "SAFEGATE_SOCKET_GUARD_ACTIVE" in local.stderr
        and "SAFEGATE_SOCKET_GUARD_ACTIVE" in offline.stderr
    )
    assert "SAFEGATE_SOCKET_ATTEMPT" not in local.stderr + offline.stderr
    assert json.loads(local.stdout) == json.loads(offline.stdout)
    assert {f["rule_id"] for f in json.loads(offline.stdout)["findings"]} == {
        "SG-001",
        "SG-002",
        "SG-003",
        "SG-004",
        "SG-006",
        "SG-009",
    }
    probe = docker(
        *command,
        "--entrypoint",
        "python",
        CLI_IMAGE,
        "-c",
        "import socket; socket.socket()",
        check=False,
    )
    assert probe.returncode == 91 and "SAFEGATE_SOCKET_ATTEMPT" in probe.stderr

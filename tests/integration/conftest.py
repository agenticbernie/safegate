"""Disposable PostgreSQL oracle; never imported by the SafeGate application."""

from __future__ import annotations

import os
import queue
import shutil
import subprocess
import threading
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field

import pytest

PG_IMAGE = "postgres:16.15-alpine@sha256:0cefaabd882e42bcb2a2f3dc56d3ce4770560ba62fd7f197f1a2e008fd5731ab"
CLI_IMAGE = os.environ.get("SAFEGATE_TEST_CLI_IMAGE", "safegate-pg16-oracle-cli:latest")
REQUIRED = os.environ.get("SAFEGATE_PG16_REQUIRED") == "1"
TIMEOUT = 30.0


def docker(
    *args: str, check: bool = True, timeout: float = TIMEOUT
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=False, timeout=timeout
    )
    if check and result.returncode:
        raise RuntimeError(
            f"Docker command failed ({result.returncode}): {args!r}; "
            f"stdout={result.stdout!r}; stderr={result.stderr!r}"
        )
    return result


def require_image(image: str) -> None:
    if not shutil.which("docker"):
        message = "Docker is unavailable; prepare the isolated integration environment"
    else:
        result = docker("image", "inspect", image, check=False)
        if result.returncode == 0:
            return
        message = f"Required image {image} is not cached or Docker is unavailable: {result.stderr.strip()}"
    if REQUIRED:
        pytest.fail(message, pytrace=False)
    pytest.skip(message)


def wait_for_postgres(name: str) -> None:
    # The image starts and stops a temporary server during initdb; pg_isready
    # can otherwise succeed before that server is shut down.
    # https://github.com/docker-library/postgres/blob/9d15534160ade17f2b6c455a39ee967c49b1937d/docker-entrypoint.sh
    marker = "PostgreSQL init process complete; ready for start up."
    deadline = time.monotonic() + TIMEOUT
    logs = ""
    while time.monotonic() < deadline:
        result = docker("logs", name, check=False)
        logs = result.stdout + result.stderr
        if marker in logs:
            ready = docker(
                "exec",
                name,
                "pg_isready",
                "-h",
                "/var/run/postgresql",
                "-U",
                "postgres",
                check=False,
            )
            if ready.returncode == 0:
                return
        time.sleep(0.2)
    pytest.fail(f"PG16 startup watchdog expired: {logs}", pytrace=False)


class Session:
    """Long-lived psql with output sentinels and bounded waits."""

    def __init__(self, container: str, database: str) -> None:
        self.process = subprocess.Popen(
            [
                "docker",
                "exec",
                "-i",
                container,
                "psql",
                "-X",
                "-q",
                "-t",
                "-A",
                "-v",
                "ON_ERROR_STOP=1",
                "-h",
                "/var/run/postgresql",
                "-U",
                "postgres",
                "-d",
                database,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self.lines: queue.Queue[str | None] = queue.Queue()
        self.output: list[str] = []
        self.pid = 0
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.pid = int(self.query("SELECT pg_backend_pid()"))

    def _read(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            self.lines.put(line.rstrip("\n"))
        self.lines.put(None)

    def start(self, sql: str) -> str:
        marker = f"sg_done_{uuid.uuid4().hex}"
        assert self.process.stdin is not None
        self.process.stdin.write(f"{sql.rstrip(';')};\nSELECT '{marker}';\n")
        self.process.stdin.flush()
        return marker

    def wait(self, marker: str, timeout: float = TIMEOUT) -> str:
        deadline = time.monotonic() + timeout
        lines: list[str] = []
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    f"psql PID {self.pid} timed out waiting for {marker}; output={self.output!r}"
                )
            try:
                line = self.lines.get(timeout=remaining)
            except queue.Empty as exc:
                raise AssertionError(
                    f"psql PID {self.pid} timed out waiting for {marker}; output={self.output!r}"
                ) from exc
            if line is None:
                raise AssertionError(
                    f"psql exited {self.process.poll()}; output={self.output!r}"
                )
            self.output.append(line)
            if line == marker:
                return "\n".join(lines)
            lines.append(line)

    def query(self, sql: str) -> str:
        return self.wait(self.start(sql))

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.process.stdin:
            self.process.stdin.close()
        if self.process.stdout:
            self.process.stdout.close()


@dataclass
class Database:
    container: str
    name: str
    sessions: list[Session] = field(default_factory=list)

    def session(self) -> Session:
        session = Session(self.container, self.name)
        self.sessions.append(session)
        return session

    def close(self) -> None:
        for session in self.sessions:
            session.close()


@pytest.fixture(scope="session")
def pg_container() -> Iterator[str]:
    require_image(PG_IMAGE)
    name = f"safegate-pg16-oracle-{uuid.uuid4().hex}"
    try:
        result = docker(
            "run",
            "-d",
            "--rm",
            "--pull=never",
            "--network=none",
            "--name",
            name,
            "--label",
            "safegate.pg16.oracle=1",
            "-e",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            PG_IMAGE,
            "-c",
            "listen_addresses=",
            "-c",
            "unix_socket_directories=/var/run/postgresql",
            check=False,
        )
        if result.returncode:
            pytest.fail(
                f"Could not start isolated PG16 container: {result.stderr}",
                pytrace=False,
            )
        wait_for_postgres(name)
        config = docker(
            "exec",
            name,
            "psql",
            "-X",
            "-A",
            "-t",
            "-U",
            "postgres",
            "-d",
            "postgres",
            "-c",
            "SHOW listen_addresses; SHOW server_version;",
        )
        assert config.stdout.splitlines() == ["", "16.15"], config.stdout
        yield name
    finally:
        # Also clean up if docker run timed out after creating the container.
        exists = docker("container", "inspect", name, check=False)
        if exists.returncode == 0:
            cleanup = docker("rm", "-f", "-v", name, check=False)
            if cleanup.returncode:
                raise RuntimeError(
                    f"Could not clean disposable PG16 container {name}: {cleanup.stderr}"
                )


@pytest.fixture
def pg_db(pg_container: str) -> Iterator[Database]:
    name = f"sg_{uuid.uuid4().hex}"
    docker(
        "exec",
        pg_container,
        "createdb",
        "-h",
        "/var/run/postgresql",
        "-U",
        "postgres",
        name,
    )
    database = Database(pg_container, name)
    try:
        yield database
    finally:
        database.close()
        cleanup = docker(
            "exec",
            pg_container,
            "dropdb",
            "-h",
            "/var/run/postgresql",
            "-U",
            "postgres",
            "--force",
            name,
            check=False,
        )
        if cleanup.returncode:
            raise RuntimeError(
                f"Could not clean disposable database {name}: {cleanup.stderr}"
            )

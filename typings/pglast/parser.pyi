from typing import Any

class ParseError(Exception): ...

class RawStmt:
    stmt: Any
    stmt_location: int
    stmt_len: int

class Token:
    start: int
    end: int
    name: str
    kind: str

def parse_sql(query: str) -> tuple[RawStmt, ...]: ...
def scan(query: str) -> list[Token]: ...
def get_postgresql_version() -> tuple[int, int, int]: ...

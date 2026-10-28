from typing import Any

__version__: str
__all__ = ["__version__", "parse_sql"]

class RawStmt:
    stmt: Any
    stmt_location: int
    stmt_len: int

def parse_sql(query: str) -> tuple[RawStmt, ...]: ...

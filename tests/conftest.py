from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from safegate.config import SafegateConfig
from safegate.scan import ScanResult, scan_file

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"


@pytest.fixture
def fixture_path() -> Callable[[str], Path]:
    return lambda name: FIXTURES / name


@pytest.fixture
def read_sql_fixture(fixture_path: Callable[[str], Path]) -> Callable[[str], str]:
    def read(name: str) -> str:
        return fixture_path(name).read_text(encoding="utf-8")

    return read


@pytest.fixture
def scan_sql_fixture(
    fixture_path: Callable[[str], Path],
) -> Callable[..., ScanResult]:
    def scan(
        name: str,
        *,
        config: SafegateConfig | None = None,
        absolute_file: bool = False,
    ) -> ScanResult:
        path = fixture_path(name)
        display_file = (
            str(path.resolve()) if absolute_file else path.relative_to(ROOT).as_posix()
        )
        return scan_file(
            path,
            display_file=display_file,
            config=config or SafegateConfig(),
        )

    return scan

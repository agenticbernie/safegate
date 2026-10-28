from __future__ import annotations

from typing import Literal

from safegate.scan import ScanStatus

FailOn = Literal["block", "review", "never"]
EXIT_SAFE = 0
EXIT_FINDING = 1
EXIT_TOOL_ERROR = 2


def exit_code(status: ScanStatus, *, fail_on: FailOn = "block") -> int:
    if status == "UNKNOWN":
        return EXIT_TOOL_ERROR
    if fail_on == "never":
        return EXIT_SAFE
    if fail_on == "block":
        return EXIT_FINDING if status == "BLOCK" else EXIT_SAFE
    return EXIT_FINDING if status in {"REVIEW", "BLOCK"} else EXIT_SAFE

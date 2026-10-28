from __future__ import annotations

import os
import sys
from pathlib import Path

from safegate.github.action import main


def _check_workspace_access() -> bool:
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if not workspace:
        return True
    path = Path(workspace)
    return path.is_dir() and os.access(path, os.R_OK | os.X_OK)


def _check_output_access() -> bool:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        return True
    try:
        with Path(output).open("a", encoding="utf-8"):
            pass
    except OSError:
        return False
    return True


if not _check_workspace_access():
    print("Safegate Action cannot read GITHUB_WORKSPACE.", file=sys.stderr)
    raise SystemExit(2)

if not _check_output_access():
    print("Safegate Action cannot write GITHUB_OUTPUT.", file=sys.stderr)
    raise SystemExit(2)

main()

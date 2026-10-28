from __future__ import annotations

from pathlib import Path
from typing import Literal

import typer
from pglast import __version__ as pglast_version
from pglast.parser import get_postgresql_version
from rich.console import Console

from safegate.config import ConfigError, load_config
from safegate.exit_codes import EXIT_TOOL_ERROR, FailOn, exit_code
from safegate.report import report_json, report_text
from safegate.scan import expand_sql_files, relative_file, scan_file

app = typer.Typer(
    name="safegate",
    help="Static PostgreSQL migration safety checks.",
    no_args_is_help=True,
    add_completion=False,
)
_PATTERN_ARGUMENT = typer.Argument(..., help="SQL file, directory, or recursive glob.")
_FORMAT_OPTION = typer.Option("text", "--format", help="Report format.")
_PG_VERSION_OPTION = typer.Option(
    None,
    "--pg-version",
    min=1,
    help="Target PostgreSQL major version (defaults to policy value or 16).",
)
_FAIL_ON_OPTION = typer.Option(
    "block",
    "--fail-on",
    help="Exit 1 on block, review, or never; parser/tool errors always exit 2.",
)
_CONFIG_OPTION = typer.Option(
    Path(".safegate.toml"),
    "--config",
    help="Path to configuration file.",
)


@app.command("scan")
def scan_command(
    pattern: str = _PATTERN_ARGUMENT,
    output_format: Literal["json", "text"] = _FORMAT_OPTION,
    pg_version: int | None = _PG_VERSION_OPTION,
    fail_on: FailOn = _FAIL_ON_OPTION,
    config_path: Path = _CONFIG_OPTION,
) -> None:
    try:
        config = load_config(config_path, pg_version_override=pg_version)
        paths = expand_sql_files(pattern)
        if not paths:
            raise ValueError(f"no .sql files matched {pattern!r}")
        root = Path.cwd()
        results = tuple(
            scan_file(path, display_file=relative_file(path, root), config=config)
            for path in paths
        )
    except (ConfigError, OSError, ValueError) as error:
        typer.echo(f"safegate: {error}", err=True)
        raise typer.Exit(code=EXIT_TOOL_ERROR) from error

    if output_format == "json":
        typer.echo(report_json(results), nl=False)
    else:
        typer.echo(report_text(results), nl=False)

    from safegate.report import build_report

    raise typer.Exit(code=exit_code(build_report(results).status, fail_on=fail_on))


@app.command("doctor")
def doctor() -> None:
    try:
        pg_version = get_postgresql_version()
    except (
        Exception
    ) as error:  # pragma: no cover - defensive against broken native extension
        typer.echo(
            f"safegate doctor: pglast unavailable: {type(error).__name__}", err=True
        )
        raise typer.Exit(code=EXIT_TOOL_ERROR) from error

    grammar_major = pg_version[0]
    if grammar_major != 16:
        typer.echo(
            f"safegate doctor: expected PostgreSQL 16 grammar, found {pg_version}.",
            err=True,
        )
        raise typer.Exit(code=EXIT_TOOL_ERROR)

    console = Console(color_system=None, force_terminal=False)
    console.print(f"Safegate doctor: PostgreSQL {grammar_major} grammar available.")
    console.print(f"pglast: {pglast_version}")
    console.print("Scan path: local only; no HTTP client configured.")


def main() -> None:
    app()

"""Typer CLI entry point for mcp-audit."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import typer
from rich.console import Console

from mcp_audit.checks.base import Severity
from mcp_audit.checks.registry import get_all_checks
from mcp_audit.config.loader import ConfigParseError
from mcp_audit.output.json_output import build_json
from mcp_audit.output.sarif import build_sarif
from mcp_audit.output.table import print_findings_table, print_summary
from mcp_audit.scanner import scan_config, scan_discovery

app = typer.Typer(
    name="mcp-audit",
    help="Security scanner for MCP server configurations.",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


class OutputFormat(str, Enum):
    """Supported output formats."""

    table = "table"
    json = "json"
    sarif = "sarif"


_SEVERITY_NAMES = {s.name: s for s in Severity}


@app.command()
def scan(
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to MCP config file"
    ),
    output: OutputFormat = typer.Option(
        OutputFormat.table, "--output", "-o", help="Output format"
    ),
    output_file: Path | None = typer.Option(
        None, "--output-file", "-f", help="Write output to file"
    ),
    min_severity: str | None = typer.Option(
        None,
        "--min-severity",
        help="Minimum severity to report: CRITICAL, HIGH, MEDIUM, LOW, INFO",
    ),
) -> None:
    """Scan MCP server configurations for security issues."""
    try:
        if config is not None:
            result = scan_config(config)
        else:
            result = scan_discovery()
            if result.configs_scanned == 0:
                err_console.print(
                    "[yellow]No MCP config files found. Use --config to specify one.[/yellow]"
                )
                raise typer.Exit(code=0)
    except ConfigParseError as exc:
        err_console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(code=2) from exc

    findings = result.findings

    # Filter by minimum severity
    if min_severity:
        threshold = _SEVERITY_NAMES.get(min_severity.upper())
        if threshold is None:
            err_console.print(
                f"[red]Invalid severity: {min_severity}. "
                f"Choose from: {', '.join(_SEVERITY_NAMES)}[/red]"
            )
            raise typer.Exit(code=2)
        findings = [f for f in findings if f.severity >= threshold]

    # Format output
    if output == OutputFormat.json:
        text = build_json(findings)
        if output_file:
            output_file.write_text(text, encoding="utf-8")
        else:
            typer.echo(text)
    elif output == OutputFormat.sarif:
        text = build_sarif(findings, result.config_path)
        if output_file:
            output_file.write_text(text, encoding="utf-8")
        else:
            typer.echo(text)
    else:
        if findings:
            print_findings_table(findings, console)
        print_summary(findings, console)

    if findings:
        raise typer.Exit(code=1)


@app.command("list-checks")
def list_checks() -> None:
    """List all available security checks."""
    from rich.table import Table

    checks = sorted(get_all_checks(), key=lambda c: c.check_id)

    table = Table(title="Available Security Checks")
    table.add_column("ID", style="bold", width=8)
    table.add_column("Title", width=30)
    table.add_column("Severity", width=10)

    severity_styles = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "white",
    }

    for check in checks:
        style = severity_styles.get(check.severity, "white")
        table.add_row(
            check.check_id,
            check.title,
            f"[{style}]{check.severity.name}[/{style}]",
        )

    console.print(table)

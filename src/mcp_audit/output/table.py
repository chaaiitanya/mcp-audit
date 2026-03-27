"""Rich terminal table output for findings."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from mcp_audit.checks.base import Finding, Severity

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "white",
}


def print_findings_table(findings: list[Finding], console: Console) -> None:
    """Print findings as a Rich table sorted by severity (most critical first)."""
    sorted_findings = sorted(findings, key=lambda f: f.severity, reverse=True)

    table = Table(title="MCP Security Findings", show_lines=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Check", width=8)
    table.add_column("Server", width=20)
    table.add_column("Title", width=30)
    table.add_column("Evidence", width=40)

    for finding in sorted_findings:
        style = _SEVERITY_STYLES.get(finding.severity, "white")
        table.add_row(
            f"[{style}]{finding.severity.name}[/{style}]",
            finding.check_id,
            finding.server_name,
            finding.title,
            finding.evidence,
        )

    console.print(table)


def print_summary(findings: list[Finding], console: Console) -> None:
    """Print a one-line summary of findings."""
    if not findings:
        console.print("[green]No findings — config looks clean.[/green]")
        return

    counts: dict[str, int] = {}
    for f in findings:
        name = f.severity.name.lower()
        counts[name] = counts.get(name, 0) + 1

    parts = [f"{v} {k}" for k, v in counts.items()]
    console.print(f"[bold]Found {len(findings)} finding(s): {', '.join(parts)}[/bold]")

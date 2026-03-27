"""Core scanner engine — orchestrates config loading, checks, and results."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from mcp_audit.checks.base import BaseCheck, Finding
from mcp_audit.checks.registry import get_all_checks
from mcp_audit.config.loader import load_config


@dataclass
class ScanResult:
    """Result of scanning one or more MCP configurations."""

    findings: list[Finding] = field(default_factory=list)
    config_path: Path | None = None
    configs_scanned: int = 0


def scan_config(
    config_path: Path,
    checks: list[BaseCheck] | None = None,
) -> ScanResult:
    """Load one config file and run all checks against it."""
    config = load_config(config_path)
    if checks is None:
        checks = get_all_checks()

    findings: list[Finding] = []
    for check in checks:
        findings.extend(check.run(config))

    return ScanResult(
        findings=findings,
        config_path=config_path,
        configs_scanned=1,
    )


def scan_discovery(
    checks: list[BaseCheck] | None = None,
) -> ScanResult:
    """Auto-discover configs and scan all found paths."""
    from mcp_audit.config.discovery import discover_configs

    paths = discover_configs()
    all_findings: list[Finding] = []

    for path in paths:
        result = scan_config(path, checks)
        all_findings.extend(result.findings)

    return ScanResult(
        findings=all_findings,
        config_path=None,
        configs_scanned=len(paths),
    )

"""MCP009: Detect world-readable MCP configuration files."""

from __future__ import annotations

import stat

from mcp_audit.checks.base import BaseCheck, Finding, Severity
from mcp_audit.checks.registry import register_check
from mcp_audit.config.models import MCPConfig


@register_check
class WorldReadableConfigCheck(BaseCheck):
    """Detect config files with world-readable permissions."""

    check_id = "MCP009"
    title = "World-readable config file"
    severity = Severity.MEDIUM

    def run(self, config: MCPConfig) -> list[Finding]:
        if config.source_path is None or not config.source_path.exists():
            return []

        mode = config.source_path.stat().st_mode
        if mode & stat.S_IROTH:
            return [
                Finding(
                    check_id=self.check_id,
                    severity=self.severity,
                    title=self.title,
                    description=(
                        "Config file is world-readable, exposing secrets to all users on system"
                    ),
                    server_name="(config file)",
                    remediation="Run: chmod 600 " + str(config.source_path),
                    evidence=f"permissions: {oct(mode)}",
                )
            ]

        return []

"""MCP003: Detect wildcard autoApprove settings."""

from __future__ import annotations

from mcp_audit.checks.base import BaseCheck, Finding, Severity
from mcp_audit.checks.registry import register_check
from mcp_audit.config.models import MCPConfig


@register_check
class WildcardAutoApproveCheck(BaseCheck):
    """Detect wildcard or blanket autoApprove that bypasses user confirmation."""

    check_id = "MCP003"
    title = "Wildcard autoApprove"
    severity = Severity.CRITICAL

    def run(self, config: MCPConfig) -> list[Finding]:
        findings: list[Finding] = []

        for server_name, server in config.mcpServers.items():
            if "*" in server.autoApprove or True in server.autoApprove:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        severity=self.severity,
                        title=self.title,
                        description=(
                        "Wildcard autoApprove allows all tool "
                        "calls without user confirmation"
                    ),
                        server_name=server_name,
                        remediation="Explicitly list only the tools you trust in autoApprove",
                        evidence=f"autoApprove = {server.autoApprove!r}",
                    )
                )

        return findings

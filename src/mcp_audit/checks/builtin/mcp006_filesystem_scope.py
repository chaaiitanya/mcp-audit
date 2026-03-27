"""MCP006: Detect overly broad filesystem access."""

from __future__ import annotations

from mcp_audit.checks.base import BaseCheck, Finding, Severity
from mcp_audit.checks.registry import register_check
from mcp_audit.config.models import MCPConfig

_BROAD_PATHS = {"/", "~", "/home", "/Users", "C:\\", "C:/"}
_FS_PACKAGES = {"server-filesystem", "@modelcontextprotocol/server-filesystem"}


def _is_broad_path(arg: str) -> bool:
    """Check if an argument represents overly broad filesystem access."""
    stripped = arg.rstrip("/\\")
    if stripped in _BROAD_PATHS or arg in _BROAD_PATHS:
        return True
    if stripped == "":
        return arg in ("/", "\\")
    return False


@register_check
class BroadFilesystemCheck(BaseCheck):
    """Detect when filesystem servers are given overly broad access paths."""

    check_id = "MCP006"
    title = "Broad filesystem access"
    severity = Severity.HIGH

    def run(self, config: MCPConfig) -> list[Finding]:
        findings: list[Finding] = []

        for server_name, server in config.mcpServers.items():
            for arg in server.args:
                if _is_broad_path(arg):
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            severity=self.severity,
                            title=self.title,
                            description=(
                                f"Overly broad filesystem path '{arg}' "
                                f"grants access to entire directory tree"
                            ),
                            server_name=server_name,
                            remediation=(
                                "Restrict filesystem access to specific project directories"
                            ),
                            evidence=f"arg: {arg}",
                        )
                    )

        return findings

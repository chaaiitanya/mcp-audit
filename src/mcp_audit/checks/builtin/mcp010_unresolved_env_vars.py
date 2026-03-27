"""MCP010: Detect unresolved environment variable references."""

from __future__ import annotations

import os
import re

from mcp_audit.checks.base import BaseCheck, Finding, Severity
from mcp_audit.checks.registry import register_check
from mcp_audit.config.models import MCPConfig

_ENV_REF = re.compile(r"\$\{([^}]+)\}")


@register_check
class UnresolvedEnvVarsCheck(BaseCheck):
    """Detect ${VAR} references that cannot be resolved."""

    check_id = "MCP010"
    title = "Unresolved env var refs"
    severity = Severity.LOW

    def run(self, config: MCPConfig) -> list[Finding]:
        findings: list[Finding] = []

        for server_name, server in config.mcpServers.items():
            # Collect all values to scan
            values_to_scan: list[tuple[str, str]] = []
            for idx, arg in enumerate(server.args):
                values_to_scan.append((f"args[{idx}]", arg))
            for key, val in server.env.items():
                values_to_scan.append((f"env.{key}", val))

            for source, value in values_to_scan:
                for match in _ENV_REF.finditer(value):
                    var_name = match.group(1)
                    if var_name not in server.env and var_name not in os.environ:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                severity=self.severity,
                                title=self.title,
                                description=(
                            f"Unresolved variable "
                            f"${{{var_name}}} in {source}"
                        ),
                                server_name=server_name,
                                remediation=(
                            f"Define '{var_name}' in the server's "
                            f"env block or set it in your shell"
                        ),
                                evidence=f"{source}: {value}",
                            )
                        )

        return findings

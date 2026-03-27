"""MCP008: Detect missing HTTPS in server URLs and configuration."""

from __future__ import annotations

import re

from mcp_audit.checks.base import BaseCheck, Finding, Severity
from mcp_audit.checks.registry import register_check
from mcp_audit.config.models import MCPConfig

_HTTP_URL = re.compile(r"\bhttp://[^\s]+")


@register_check
class MissingHTTPSCheck(BaseCheck):
    """Detect insecure HTTP URLs and Docker-based servers lacking HTTPS."""

    check_id = "MCP008"
    title = "Missing HTTPS"
    severity = Severity.MEDIUM

    def run(self, config: MCPConfig) -> list[Finding]:
        findings: list[Finding] = []

        for server_name, server in config.mcpServers.items():
            # Check explicit url field
            if server.url and server.url.startswith("http://"):
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        severity=self.severity,
                        title=self.title,
                        description=(
                        "Server URL uses HTTP instead of HTTPS"
                    ),
                        server_name=server_name,
                        remediation="Use HTTPS URLs for all server connections",
                        evidence=f"url: {server.url}",
                    )
                )

            # Check args for HTTP URLs
            for idx, arg in enumerate(server.args):
                if _HTTP_URL.search(arg):
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            severity=self.severity,
                            title=self.title,
                            description=f"HTTP URL found in args[{idx}]",
                            server_name=server_name,
                            remediation="Use HTTPS URLs for all server connections",
                            evidence=f"args[{idx}] = {arg[:50]}",
                        )
                    )

            # Check env for HTTP URLs
            for key, value in server.env.items():
                if _HTTP_URL.search(value):
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            severity=self.severity,
                            title=self.title,
                            description=f"HTTP URL found in env var '{key}'",
                            server_name=server_name,
                            remediation="Use HTTPS URLs for all server connections",
                            evidence=f"env.{key} = {value[:50]}",
                        )
                    )

        return findings

"""MCP002: Detect credentials passed in command-line arguments."""

from __future__ import annotations

import re

from mcp_audit.checks.base import BaseCheck, Finding, Severity
from mcp_audit.checks.registry import register_check
from mcp_audit.config.models import MCPConfig

_GITHUB_PAT = re.compile(r"ghp_[A-Za-z0-9]{36}")
_OPENAI_KEY = re.compile(r"sk-[A-Za-z0-9]{48}")
_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_JWT = re.compile(r"eyJhbGci[A-Za-z0-9._-]+")
_SUPABASE = re.compile(r"sbp_[a-f0-9]{40}")
_GENERIC = re.compile(r"(?i)(password|secret|token)=(?!\$\{)[^\s]{8,}")
_AUTH_URL = re.compile(r"://[^/\s]+:[^/\s]+@")

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("GitHub PAT", _GITHUB_PAT),
    ("OpenAI API key", _OPENAI_KEY),
    ("AWS access key", _AWS_KEY),
    ("JWT token", _JWT),
    ("Supabase key", _SUPABASE),
    ("Generic credential", _GENERIC),
    ("Embedded URL credentials", _AUTH_URL),
]


@register_check
class CredentialsInArgsCheck(BaseCheck):
    """Detect credentials passed as command-line arguments."""

    check_id = "MCP002"
    title = "Credentials in args"
    severity = Severity.CRITICAL

    def run(self, config: MCPConfig) -> list[Finding]:
        findings: list[Finding] = []

        for server_name, server in config.mcpServers.items():
            for idx, arg in enumerate(server.args):
                for pattern_name, pattern in _PATTERNS:
                    if pattern.search(arg):
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                severity=self.severity,
                                title=self.title,
                                description=f"{pattern_name} detected in args[{idx}]",
                                server_name=server_name,
                                remediation=(
                                    "Pass credentials via environment "
                                    "variables, not command-line arguments"
                                ),
                                evidence=f"args[{idx}] = {arg[:20]}...",
                            )
                        )
                        break

        return findings

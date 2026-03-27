"""MCP004: Detect tool poisoning patterns in descriptions and string values."""

from __future__ import annotations

import re
from typing import Any

from mcp_audit.checks.base import BaseCheck, Finding, Severity
from mcp_audit.checks.registry import register_check
from mcp_audit.config.models import MCPConfig

_HTML_TAGS = re.compile(r"<(IMPORTANT|HIDDEN|INSTRUCTION|s)\b", re.IGNORECASE)
_EXFIL = re.compile(r"(read|send|access|copy).*(\.ssh|\.aws|\.env|mcp\.json)", re.IGNORECASE)
_CROSS_TOOL = re.compile(r"when\s+(tool|function)\s+\w+\s+is\s+called", re.IGNORECASE)
_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_SOCIAL_ENG = re.compile(
    r"(do not tell the user|required for authentication)", re.IGNORECASE
)
_BASE64_PAYLOAD = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

_POISONING_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("HTML injection tag", _HTML_TAGS),
    ("Data exfiltration path", _EXFIL),
    ("Cross-tool injection", _CROSS_TOOL),
    ("Zero-width characters", _ZERO_WIDTH),
    ("Social engineering", _SOCIAL_ENG),
    ("Suspicious Base64 payload", _BASE64_PAYLOAD),
]


def _extract_strings(obj: Any) -> list[str]:
    """Recursively extract all string values from a nested structure."""
    strings: list[str] = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            strings.extend(_extract_strings(v))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            strings.extend(_extract_strings(item))
    return strings


@register_check
class ToolPoisoningCheck(BaseCheck):
    """Detect tool poisoning patterns in MCP server configuration values."""

    check_id = "MCP004"
    title = "Tool poisoning in description"
    severity = Severity.HIGH

    def run(self, config: MCPConfig) -> list[Finding]:
        findings: list[Finding] = []

        for server_name, server in config.mcpServers.items():
            # Collect all scannable strings
            strings: list[str] = []
            strings.extend(server.args)
            strings.extend(server.env.values())
            if server.model_extra:
                strings.extend(_extract_strings(server.model_extra))

            for text in strings:
                for pattern_name, pattern in _POISONING_PATTERNS:
                    match = pattern.search(text)
                    if match:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                severity=self.severity,
                                title=self.title,
                                description=f"{pattern_name} detected in server configuration",
                                server_name=server_name,
                                remediation=(
                            "Review server configuration for "
                            "injected instructions or suspicious content"
                        ),
                                evidence=f"Match: {match.group()[:50]}",
                            )
                        )
                        break  # one finding per string

        return findings

"""MCP005: Detect full-schema poisoning in tool definitions."""

from __future__ import annotations

import re
from typing import Any

from mcp_audit.checks.base import BaseCheck, Finding, Severity
from mcp_audit.checks.registry import register_check
from mcp_audit.config.models import MCPConfig

_SCHEMA_KEYS = {"tools", "schema", "inputSchema", "parameters", "definitions"}

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


def _scan_schema(obj: Any, depth: int = 0) -> list[str]:
    """Extract description strings from nested schema objects."""
    if depth > 20:
        return []
    descriptions: list[str] = []
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key == "description" and isinstance(val, str):
                descriptions.append(val)
            else:
                descriptions.extend(_scan_schema(val, depth + 1))
    elif isinstance(obj, list):
        for item in obj:
            descriptions.extend(_scan_schema(item, depth + 1))
    return descriptions


@register_check
class FullSchemaPoisoningCheck(BaseCheck):
    """Detect poisoning patterns within tool schema definitions."""

    check_id = "MCP005"
    title = "Full-schema poisoning"
    severity = Severity.HIGH

    def run(self, config: MCPConfig) -> list[Finding]:
        findings: list[Finding] = []

        for server_name, server in config.mcpServers.items():
            if not server.model_extra:
                continue

            # Find schema-like nested objects
            for key in _SCHEMA_KEYS & server.model_extra.keys():
                descriptions = _scan_schema(server.model_extra[key])

                for desc in descriptions:
                    for pattern_name, pattern in _POISONING_PATTERNS:
                        match = pattern.search(desc)
                        if match:
                            findings.append(
                                Finding(
                                    check_id=self.check_id,
                                    severity=self.severity,
                                    title=self.title,
                                    description=f"{pattern_name} in tool schema '{key}'",
                                    server_name=server_name,
                                    remediation=(
                            "Inspect tool schema definitions "
                            "for injected instructions"
                        ),
                                    evidence=f"Match: {match.group()[:50]}",
                                )
                            )
                            break

        return findings

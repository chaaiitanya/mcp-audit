"""MCP001: Detect plaintext secrets in server environment variables."""

from __future__ import annotations

import math
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
_ENV_VAR_REF = re.compile(r"^\$\{[^}]+\}$")

_NAMED_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("GitHub PAT", _GITHUB_PAT),
    ("OpenAI API key", _OPENAI_KEY),
    ("AWS access key", _AWS_KEY),
    ("JWT token", _JWT),
    ("Supabase key", _SUPABASE),
    ("Generic credential", _GENERIC),
]

_PUBLIC_KEY_HINTS = {"CERT", "PUBKEY", "PUBLIC", "CERTIFICATE"}


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


@register_check
class PlaintextSecretsCheck(BaseCheck):
    """Detect plaintext secrets in MCP server environment variables."""

    check_id = "MCP001"
    title = "Plaintext secrets in env"
    severity = Severity.CRITICAL

    def run(self, config: MCPConfig) -> list[Finding]:
        findings: list[Finding] = []

        for server_name, server in config.mcpServers.items():
            for key, value in server.env.items():
                if _ENV_VAR_REF.match(value):
                    continue

                # Check named patterns
                for pattern_name, pattern in _NAMED_PATTERNS:
                    if pattern.search(value):
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                severity=self.severity,
                                title=self.title,
                                description=f"{pattern_name} detected in env var '{key}'",
                                server_name=server_name,
                                remediation=(
                                    "Use environment variable references "
                                    "like ${VAR} instead of plaintext secrets"
                                ),
                                evidence=f"env.{key} = {value[:20]}...",
                            )
                        )
                        break  # one finding per key
                else:
                    # High-entropy check
                    is_public = any(hint in key.upper() for hint in _PUBLIC_KEY_HINTS)
                    if not is_public and len(value) > 20 and _shannon_entropy(value) > 4.5:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                severity=self.severity,
                                title=self.title,
                                description=(
                                    f"High-entropy value in env var '{key}' (possible secret)"
                                ),
                                server_name=server_name,
                                remediation=(
                                    "Use environment variable references "
                                    "like ${VAR} instead of plaintext secrets"
                                ),
                                evidence=f"env.{key} = {value[:20]}...",
                            )
                        )

        return findings

"""Base classes for all mcp-audit security checks."""

from __future__ import annotations

import abc
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_audit.config.models import MCPConfig


class Severity(IntEnum):
    """Severity levels for security findings."""

    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class Finding:
    """A single security finding produced by a check."""

    check_id: str
    severity: Severity
    title: str
    description: str
    server_name: str
    remediation: str
    evidence: str = ""


class BaseCheck(abc.ABC):
    """Abstract base class for all security checks."""

    check_id: str
    title: str
    severity: Severity

    @abc.abstractmethod
    def run(self, config: MCPConfig) -> list[Finding]:
        """Run the check against an MCP configuration and return findings."""
        ...

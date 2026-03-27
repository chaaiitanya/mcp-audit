"""MCP011: Detect known vulnerable MCP packages."""

from __future__ import annotations

import importlib.resources
import json

from mcp_audit.checks.base import BaseCheck, Finding, Severity
from mcp_audit.checks.registry import register_check
from mcp_audit.config.models import MCPConfig

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

_SKIP_COMMANDS = {"npx", "npx.cmd", "uvx", "node", "python", "python3"}


def _extract_package_name(arg: str) -> str | None:
    """Extract package name from a command argument, stripping version suffixes."""
    if arg.startswith("-"):
        return None
    if arg in _SKIP_COMMANDS:
        return None

    if arg.startswith("@"):
        # Scoped: @scope/package or @scope/package@version
        rest = arg[1:]
        if "/" not in rest:
            return None
        after_scope = rest.split("/", 1)[1]
        if "@" in after_scope:
            return arg.rsplit("@", 1)[0]
        return arg
    else:
        # Unscoped: package or package@version
        if "@" in arg:
            return arg.rsplit("@", 1)[0]
        return arg


@register_check
class KnownCVEsCheck(BaseCheck):
    """Detect packages with known security vulnerabilities."""

    check_id = "MCP011"
    title = "Known vulnerable packages"
    severity = Severity.HIGH

    def __init__(self) -> None:
        ref = importlib.resources.files("mcp_audit.data").joinpath("cve_list.json")
        self._cves: dict[str, dict[str, str]] = json.loads(ref.read_text())

    def run(self, config: MCPConfig) -> list[Finding]:
        findings: list[Finding] = []

        for server_name, server in config.mcpServers.items():
            # Check command itself
            all_args = [server.command] + server.args

            seen: set[str] = set()
            for arg in all_args:
                pkg = _extract_package_name(arg)
                if pkg is None or pkg in seen:
                    continue
                seen.add(pkg)

                if pkg in self._cves:
                    cve = self._cves[pkg]
                    sev = _SEVERITY_MAP.get(cve.get("severity", "HIGH"), Severity.HIGH)
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            severity=sev,
                            title=self.title,
                            description=(
                                f"Package '{pkg}' has {cve['cve_id']}: {cve['description']}"
                            ),
                            server_name=server_name,
                            remediation=f"Update or replace '{pkg}' — see {cve['cve_id']}",
                            evidence=f"package: {pkg}, CVE: {cve['cve_id']}",
                        )
                    )

        return findings

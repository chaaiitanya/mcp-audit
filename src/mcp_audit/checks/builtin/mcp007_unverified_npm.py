"""MCP007: Detect unverified npx packages without pinned versions."""

from __future__ import annotations

from mcp_audit.checks.base import BaseCheck, Finding, Severity
from mcp_audit.checks.registry import register_check
from mcp_audit.config.models import MCPConfig

_SKIP_ARGS = {"-y", "--yes", "-q", "--quiet"}


def _is_pinned(package_arg: str) -> bool:
    """Check if a package argument has a pinned version."""
    if package_arg.startswith("@"):
        # Scoped package: @scope/package or @scope/package@version
        rest = package_arg[1:]
        if "/" not in rest:
            return False
        after_scope = rest.split("/", 1)[1]
        return "@" in after_scope
    return "@" in package_arg


def _is_package_name(arg: str) -> bool:
    """Check if an arg looks like a package name (not a flag or path)."""
    if arg.startswith("-"):
        return False
    if arg in _SKIP_ARGS:
        return False
    return not ("/" in arg and not arg.startswith("@"))


@register_check
class UnverifiedNpxCheck(BaseCheck):
    """Detect npx packages running without pinned versions."""

    check_id = "MCP007"
    title = "Unverified npx packages"
    severity = Severity.MEDIUM

    def run(self, config: MCPConfig) -> list[Finding]:
        findings: list[Finding] = []

        for server_name, server in config.mcpServers.items():
            if server.command not in ("npx", "npx.cmd"):
                continue
            if "-y" not in server.args and "--yes" not in server.args:
                continue

            for arg in server.args:
                if not _is_package_name(arg):
                    continue
                if arg in ("npx", "npx.cmd"):
                    continue
                if not _is_pinned(arg):
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            severity=self.severity,
                            title=self.title,
                            description=(
                        f"Package '{arg}' runs via npx -y "
                        f"without a pinned version"
                    ),
                            server_name=server_name,
                            remediation=f"Pin the version: {arg}@<version> or use a SHA hash",
                            evidence=f"package: {arg}",
                        )
                    )

        return findings

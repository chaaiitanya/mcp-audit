"""MCP012: Detect tool definition changes (rug pull / supply chain attack)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from platformdirs import user_data_dir

from mcp_audit.checks.base import BaseCheck, Finding, Severity
from mcp_audit.checks.registry import register_check
from mcp_audit.config.models import MCPConfig


@register_check
class RugPullCheck(BaseCheck):
    """Detect changes to tool definitions between scans."""

    check_id = "MCP012"
    title = "Rug pull detection"
    severity = Severity.MEDIUM

    baseline_path: Path = Path(user_data_dir("mcp-audit")) / "baselines.json"

    def _load_baseline(self) -> dict[str, dict[str, str]]:
        """Load existing baseline or return empty dict."""
        if self.baseline_path.exists():
            data: dict[str, dict[str, str]] = json.loads(
                self.baseline_path.read_text(encoding="utf-8")
            )
            return data
        return {}

    def _save_baseline(self, baseline: dict[str, dict[str, str]]) -> None:
        """Write baseline to disk."""
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")

    @staticmethod
    def _hash_tools(tools: Any) -> str:
        """Compute SHA-256 hash of a tool definition."""
        return hashlib.sha256(json.dumps(tools, sort_keys=True).encode()).hexdigest()

    def run(self, config: MCPConfig) -> list[Finding]:
        findings: list[Finding] = []
        baseline = self._load_baseline()

        for server_name, server in config.mcpServers.items():
            if not server.model_extra or "tools" not in server.model_extra:
                continue

            tools = server.model_extra["tools"]
            current_hash = self._hash_tools(tools)

            if server_name in baseline:
                for tool_name, stored_hash in baseline[server_name].items():
                    if tool_name in ("_all_",) and stored_hash != current_hash:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                severity=self.severity,
                                title=self.title,
                                description=(
                                    f"Tool definitions for '{server_name}' changed since last scan"
                                ),
                                server_name=server_name,
                                remediation=("Verify the tool definition changes are intentional"),
                                evidence=(
                                    f"previous hash: {stored_hash[:16]}..., "
                                    f"current: {current_hash[:16]}..."
                                ),
                            )
                        )

            # Update baseline
            baseline[server_name] = {"_all_": current_hash}

        self._save_baseline(baseline)
        return findings

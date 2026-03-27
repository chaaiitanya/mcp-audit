"""Tests for MCP011: Known vulnerable packages."""

from mcp_audit.checks.base import Severity
from mcp_audit.checks.builtin.mcp011_known_cves import KnownCVEsCheck


class TestKnownCVEs:
    def setup_method(self):
        self.check = KnownCVEsCheck()

    def test_safe_package_no_findings(self, make_config):
        config = make_config({"srv": {"command": "npx", "args": ["-y", "safe-package@1.0.0"]}})
        assert self.check.run(config) == []

    def test_vulnerable_package_detected(self, make_config):
        config = make_config({"srv": {"command": "npx", "args": ["-y", "mcp-remote"]}})
        findings = self.check.run(config)
        assert len(findings) == 1
        assert findings[0].check_id == "MCP011"
        assert "CVE-2025-6514" in findings[0].evidence

    def test_scoped_vulnerable_package(self, make_config):
        pkg = "@modelcontextprotocol/inspector"
        config = make_config({"srv": {"command": "npx", "args": ["-y", pkg]}})
        findings = self.check.run(config)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_versioned_still_flagged(self, make_config):
        config = make_config({"srv": {"command": "npx", "args": ["-y", "mcp-remote@0.1.0"]}})
        findings = self.check.run(config)
        assert len(findings) == 1

    def test_invalid_scoped_package_ignored(self, make_config):
        """@scope without /package returns None from _extract_package_name."""
        config = make_config({"srv": {"command": "npx", "args": ["-y", "@invalidscope"]}})
        assert self.check.run(config) == []

    def test_scoped_versioned_package_extracted(self, make_config):
        """@scope/package@version should strip version and match CVE."""
        pkg = "@modelcontextprotocol/inspector@1.0.0"
        config = make_config({"srv": {"command": "npx", "args": ["-y", pkg]}})
        findings = self.check.run(config)
        assert len(findings) == 1
        assert "CVE-2025-49596" in findings[0].evidence

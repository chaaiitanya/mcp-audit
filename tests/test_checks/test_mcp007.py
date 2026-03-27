"""Tests for MCP007: Unverified npx packages."""

from mcp_audit.checks.base import Severity
from mcp_audit.checks.builtin.mcp007_unverified_npm import UnverifiedNpxCheck


class TestUnverifiedNpx:
    def setup_method(self):
        self.check = UnverifiedNpxCheck()

    def test_non_npx_ignored(self, make_config):
        config = make_config({"srv": {"command": "node", "args": ["server.js"]}})
        assert self.check.run(config) == []

    def test_pinned_version_ok(self, make_config):
        config = make_config({"srv": {"command": "npx", "args": ["-y", "some-package@1.2.3"]}})
        assert self.check.run(config) == []

    def test_unpinned_flagged(self, make_config):
        config = make_config({"srv": {"command": "npx", "args": ["-y", "some-package"]}})
        findings = self.check.run(config)
        assert len(findings) == 1
        assert findings[0].check_id == "MCP007"
        assert findings[0].severity == Severity.MEDIUM

    def test_scoped_pinned_ok(self, make_config):
        config = make_config({"srv": {"command": "npx", "args": ["-y", "@scope/package@2.0.0"]}})
        assert self.check.run(config) == []

    def test_scoped_unpinned_flagged(self, make_config):
        config = make_config({"srv": {"command": "npx", "args": ["-y", "@scope/package"]}})
        assert len(self.check.run(config)) == 1

    def test_no_dash_y_ignored(self, make_config):
        config = make_config({"srv": {"command": "npx", "args": ["some-package"]}})
        assert self.check.run(config) == []

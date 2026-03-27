"""Tests for MCP006: Broad filesystem access."""

from mcp_audit.checks.base import Severity
from mcp_audit.checks.builtin.mcp006_filesystem_scope import BroadFilesystemCheck


class TestBroadFilesystem:
    def setup_method(self):
        self.check = BroadFilesystemCheck()

    def test_specific_path_ok(self, make_config):
        config = make_config(
            {"srv": {"command": "npx", "args": ["-y", "fs", "/home/user/project"]}}
        )
        assert self.check.run(config) == []

    def test_root_path_flagged(self, make_config):
        config = make_config({"srv": {"command": "npx", "args": ["-y", "server-filesystem", "/"]}})
        findings = self.check.run(config)
        assert len(findings) == 1
        assert findings[0].check_id == "MCP006"
        assert findings[0].severity == Severity.HIGH

    def test_home_tilde_flagged(self, make_config):
        config = make_config({"srv": {"command": "npx", "args": ["server-filesystem", "~"]}})
        assert len(self.check.run(config)) == 1

    def test_users_path_flagged(self, make_config):
        config = make_config({"srv": {"command": "npx", "args": ["fs-server", "/Users"]}})
        assert len(self.check.run(config)) == 1

    def test_bare_backslash_flagged(self, make_config):
        config = make_config({"srv": {"command": "npx", "args": ["fs-server", "\\"]}})
        assert len(self.check.run(config)) == 1

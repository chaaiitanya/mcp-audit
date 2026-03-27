"""Tests for MCP010: Unresolved env var refs."""

from mcp_audit.checks.base import Severity
from mcp_audit.checks.builtin.mcp010_unresolved_env_vars import UnresolvedEnvVarsCheck


class TestUnresolvedEnvVars:
    def setup_method(self):
        self.check = UnresolvedEnvVarsCheck()

    def test_no_refs_no_findings(self, make_config):
        config = make_config({"srv": {"command": "node", "env": {"PORT": "3000"}}})
        assert self.check.run(config) == []

    def test_resolved_in_env_ok(self, make_config):
        config = make_config({
            "srv": {"command": "node", "env": {"URL": "${HOST}", "HOST": "localhost"}}
        })
        assert self.check.run(config) == []

    def test_unresolved_flagged(self, make_config, monkeypatch):
        monkeypatch.delenv("MISSING_VAR", raising=False)
        config = make_config({"srv": {"command": "node", "env": {"URL": "${MISSING_VAR}"}}})
        findings = self.check.run(config)
        assert len(findings) == 1
        assert findings[0].check_id == "MCP010"
        assert findings[0].severity == Severity.LOW

    def test_resolved_via_os_environ(self, make_config, monkeypatch):
        monkeypatch.setenv("MY_REAL_VAR", "value")
        config = make_config({"srv": {"command": "node", "args": ["--url=${MY_REAL_VAR}"]}})
        assert self.check.run(config) == []

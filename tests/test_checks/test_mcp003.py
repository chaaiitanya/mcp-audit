"""Tests for MCP003: Wildcard autoApprove."""

from mcp_audit.checks.base import Severity
from mcp_audit.checks.builtin.mcp003_wildcard_approve import WildcardAutoApproveCheck


class TestWildcardAutoApprove:
    def setup_method(self):
        self.check = WildcardAutoApproveCheck()

    def test_no_auto_approve(self, make_config):
        config = make_config({"srv": {"command": "node"}})
        assert self.check.run(config) == []

    def test_specific_tools_ok(self, make_config):
        config = make_config({"srv": {"command": "node", "autoApprove": ["read_file", "list_dir"]}})
        assert self.check.run(config) == []

    def test_wildcard_string_detected(self, make_config):
        config = make_config({"srv": {"command": "node", "autoApprove": "*"}})
        findings = self.check.run(config)
        assert len(findings) == 1
        assert findings[0].check_id == "MCP003"
        assert findings[0].severity == Severity.CRITICAL

    def test_wildcard_in_list_detected(self, make_config):
        config = make_config({"srv": {"command": "node", "autoApprove": ["*"]}})
        assert len(self.check.run(config)) == 1

    def test_boolean_true_detected(self, make_config):
        config = make_config({"srv": {"command": "node", "autoApprove": True}})
        assert len(self.check.run(config)) == 1

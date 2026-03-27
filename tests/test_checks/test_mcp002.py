"""Tests for MCP002: Credentials in args."""

from mcp_audit.checks.base import Severity
from mcp_audit.checks.builtin.mcp002_credentials_in_args import CredentialsInArgsCheck


class TestCredentialsInArgs:
    def setup_method(self):
        self.check = CredentialsInArgsCheck()

    def test_clean_args_no_findings(self, make_config):
        config = make_config({"srv": {"command": "node", "args": ["server.js", "--port", "3000"]}})
        assert self.check.run(config) == []

    def test_github_pat_in_args(self, make_config):
        config = make_config({"srv": {"command": "node", "args": ["--token", "ghp_" + "A" * 36]}})
        findings = self.check.run(config)
        assert len(findings) == 1
        assert findings[0].check_id == "MCP002"
        assert findings[0].severity == Severity.CRITICAL

    def test_url_with_credentials(self, make_config):
        config = make_config(
            {"srv": {"command": "node", "args": ["https://user:pass@host.com/db"]}}
        )
        findings = self.check.run(config)
        assert len(findings) == 1

    def test_safe_url_no_findings(self, make_config):
        config = make_config({"srv": {"command": "node", "args": ["https://host.com/api"]}})
        assert self.check.run(config) == []

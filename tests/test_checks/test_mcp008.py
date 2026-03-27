"""Tests for MCP008: Missing HTTPS."""

from mcp_audit.checks.base import Severity
from mcp_audit.checks.builtin.mcp008_missing_https import MissingHTTPSCheck


class TestMissingHTTPS:
    def setup_method(self):
        self.check = MissingHTTPSCheck()

    def test_https_url_ok(self, make_config):
        config = make_config({"srv": {"command": "node", "args": ["https://api.example.com"]}})
        assert self.check.run(config) == []

    def test_http_url_in_args_flagged(self, make_config):
        config = make_config({"srv": {"command": "node", "args": ["http://api.example.com"]}})
        findings = self.check.run(config)
        assert len(findings) == 1
        assert findings[0].check_id == "MCP008"
        assert findings[0].severity == Severity.MEDIUM

    def test_http_url_in_env_flagged(self, make_config):
        config = make_config({"srv": {"command": "node", "env": {"URL": "http://api.example.com"}}})
        assert len(self.check.run(config)) == 1

    def test_http_in_url_field(self, make_config):
        config = make_config({"srv": {"command": "node", "url": "http://localhost:8080"}})
        assert len(self.check.run(config)) == 1

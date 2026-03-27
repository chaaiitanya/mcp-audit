"""Tests for MCP001: Plaintext secrets in env."""

from mcp_audit.checks.base import Severity
from mcp_audit.checks.builtin.mcp001_plaintext_secrets import PlaintextSecretsCheck


class TestPlaintextSecrets:
    def setup_method(self):
        self.check = PlaintextSecretsCheck()

    def test_clean_env_no_findings(self, make_config):
        config = make_config({"srv": {"command": "node", "env": {"PORT": "3000"}}})
        assert self.check.run(config) == []

    def test_github_pat_detected(self, make_config):
        config = make_config({"srv": {"command": "node", "env": {"TOKEN": "ghp_" + "A" * 36}}})
        findings = self.check.run(config)
        assert len(findings) == 1
        assert findings[0].check_id == "MCP001"
        assert findings[0].severity == Severity.CRITICAL

    def test_openai_key_detected(self, make_config):
        config = make_config({"srv": {"command": "node", "env": {"KEY": "sk-" + "a" * 48}}})
        findings = self.check.run(config)
        assert len(findings) == 1

    def test_aws_key_detected(self, make_config):
        config = make_config({"srv": {"command": "node", "env": {"AWS": "AKIA" + "A" * 16}}})
        assert len(self.check.run(config)) == 1

    def test_env_var_ref_not_flagged(self, make_config):
        config = make_config({"srv": {"command": "node", "env": {"API_KEY": "${API_KEY}"}}})
        assert self.check.run(config) == []

    def test_high_entropy_detected(self, make_config):
        # Random-looking string with high entropy
        secret = "aB3$kL9!mN2@pQ5&rT8*vX1#yZ4%cF7"
        config = make_config({"srv": {"command": "node", "env": {"SECRET": secret}}})
        findings = self.check.run(config)
        assert len(findings) == 1

    def test_public_key_hint_skips_entropy(self, make_config):
        long_val = "aB3$kL9!mN2@pQ5&rT8*vX1#yZ4%cF7"
        config = make_config({"srv": {"command": "node", "env": {"PUBLIC_CERT": long_val}}})
        assert self.check.run(config) == []

    def test_empty_env_value_no_findings(self, make_config):
        config = make_config({"srv": {"command": "node", "env": {"KEY": ""}}})
        assert self.check.run(config) == []

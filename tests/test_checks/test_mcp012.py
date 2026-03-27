"""Tests for MCP012: Rug pull detection."""


from mcp_audit.checks.builtin.mcp012_rug_pull import RugPullCheck


class TestRugPull:
    def setup_method(self):
        self.check = RugPullCheck()

    def test_no_tools_no_findings(self, make_config):
        config = make_config({"srv": {"command": "node"}})
        assert self.check.run(config) == []

    def test_first_scan_creates_baseline(self, make_config, tmp_path):
        self.check.baseline_path = tmp_path / "baselines.json"
        config = make_config({"srv": {"command": "node", "tools": [{"name": "read"}]}})
        findings = self.check.run(config)
        assert findings == []
        assert self.check.baseline_path.exists()

    def test_changed_tools_detected(self, make_config, tmp_path):
        self.check.baseline_path = tmp_path / "baselines.json"

        # First scan — establishes baseline
        config1 = make_config({"srv": {"command": "node", "tools": [{"name": "read"}]}})
        self.check.run(config1)

        # Second scan with different tools
        config2 = make_config({"srv": {"command": "node", "tools": [{"name": "write"}]}})
        findings = self.check.run(config2)
        assert len(findings) == 1
        assert findings[0].check_id == "MCP012"

    def test_unchanged_tools_no_findings(self, make_config, tmp_path):
        self.check.baseline_path = tmp_path / "baselines.json"
        tools = [{"name": "read", "description": "Read files"}]

        config = make_config({"srv": {"command": "node", "tools": tools}})
        self.check.run(config)
        findings = self.check.run(config)
        assert findings == []

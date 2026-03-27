"""Tests for the CLI entry point."""

import json
import os

from typer.testing import CliRunner

from mcp_audit.cli import app

runner = CliRunner()


class TestScanCommand:
    def test_clean_config_exits_zero(self, make_config_path):
        path = make_config_path({"srv": {"command": "node", "env": {"PORT": "3000"}}})
        os.chmod(path, 0o600)
        result = runner.invoke(app, ["scan", "--config", str(path)])
        assert result.exit_code == 0

    def test_findings_exit_one(self, make_config_path):
        path = make_config_path({"srv": {"command": "node", "autoApprove": "*"}})
        result = runner.invoke(app, ["scan", "--config", str(path)])
        assert result.exit_code == 1

    def test_missing_file_exits_two(self):
        result = runner.invoke(app, ["scan", "--config", "/nonexistent/path.json"])
        assert result.exit_code == 2

    def test_json_output(self, make_config_path):
        path = make_config_path({"srv": {"command": "node", "autoApprove": "*"}})
        result = runner.invoke(app, ["scan", "--config", str(path), "--output", "json"])
        assert result.exit_code == 1
        parsed = json.loads(result.output)
        assert len(parsed) >= 1

    def test_sarif_output(self, make_config_path):
        path = make_config_path({"srv": {"command": "node", "autoApprove": "*"}})
        result = runner.invoke(app, ["scan", "--config", str(path), "--output", "sarif"])
        assert result.exit_code == 1
        parsed = json.loads(result.output)
        assert parsed["version"] == "2.1.0"

    def test_output_file(self, make_config_path, tmp_path):
        path = make_config_path({"srv": {"command": "node", "autoApprove": "*"}})
        out = tmp_path / "report.json"
        result = runner.invoke(
            app, ["scan", "--config", str(path), "--output", "json", "--output-file", str(out)]
        )
        assert result.exit_code == 1
        assert out.exists()
        assert json.loads(out.read_text())

    def test_min_severity_filter(self, make_config_path):
        # MCP010 is LOW — should be filtered out with min-severity HIGH
        path = make_config_path({"srv": {"command": "node", "env": {"URL": "${MISSING}"}}})
        result = runner.invoke(
            app, ["scan", "--config", str(path), "--output", "json", "--min-severity", "HIGH"]
        )
        # No HIGH+ findings from just unresolved env vars, so exit 0
        assert result.exit_code == 0


class TestListChecks:
    def test_lists_all_checks(self):
        result = runner.invoke(app, ["list-checks"])
        assert result.exit_code == 0
        assert "MCP001" in result.output
        assert "MCP012" in result.output

"""End-to-end integration tests: full pipeline scan through CLI."""

from __future__ import annotations

import json
import os
from pathlib import Path

from mcp_audit.checks.base import Severity
from mcp_audit.cli import app
from mcp_audit.scanner import scan_config
from typer.testing import CliRunner

runner = CliRunner()

FIXTURES = Path(__file__).parent / "fixtures"
E2E_CONFIG = FIXTURES / "e2e_all_vulns.json"


class TestFullPipelineScan:
    """Scan a config that triggers MCP001-MCP003, MCP006-MCP008, MCP010-MCP011."""

    def test_scan_config_returns_findings_for_all_triggered_checks(self) -> None:
        result = scan_config(E2E_CONFIG)
        check_ids = {f.check_id for f in result.findings}

        # These checks should all fire against e2e_all_vulns.json
        assert "MCP001" in check_ids, "MCP001 (plaintext secrets) not triggered"
        assert "MCP002" in check_ids, "MCP002 (credentials in args) not triggered"
        assert "MCP003" in check_ids, "MCP003 (wildcard autoApprove) not triggered"
        assert "MCP006" in check_ids, "MCP006 (broad filesystem) not triggered"
        assert "MCP007" in check_ids, "MCP007 (unverified npx) not triggered"
        assert "MCP008" in check_ids, "MCP008 (missing HTTPS) not triggered"
        assert "MCP010" in check_ids, "MCP010 (unresolved env var) not triggered"
        assert "MCP011" in check_ids, "MCP011 (known CVE) not triggered"

    def test_findings_have_correct_server_attribution(self) -> None:
        result = scan_config(E2E_CONFIG)

        server_map: dict[str, set[str]] = {}
        for f in result.findings:
            server_map.setdefault(f.check_id, set()).add(f.server_name)

        assert "secrets-in-env" in server_map.get("MCP001", set())
        assert "creds-in-args" in server_map.get("MCP002", set())
        assert "wildcard-approve" in server_map.get("MCP003", set())
        assert "broad-filesystem" in server_map.get("MCP006", set())
        assert "missing-https" in server_map.get("MCP008", set())
        assert "unresolved-env" in server_map.get("MCP010", set())
        assert "known-cve" in server_map.get("MCP011", set())

    def test_severity_levels_are_correct(self) -> None:
        result = scan_config(E2E_CONFIG)

        severity_map: dict[str, Severity] = {}
        for f in result.findings:
            severity_map[f.check_id] = f.severity

        assert severity_map["MCP001"] == Severity.CRITICAL
        assert severity_map["MCP002"] == Severity.CRITICAL
        assert severity_map["MCP003"] == Severity.CRITICAL
        assert severity_map["MCP006"] == Severity.HIGH
        assert severity_map["MCP007"] == Severity.MEDIUM
        assert severity_map["MCP008"] == Severity.MEDIUM
        assert severity_map["MCP010"] == Severity.LOW
        assert severity_map["MCP011"] >= Severity.HIGH

    def test_all_findings_have_remediation(self) -> None:
        result = scan_config(E2E_CONFIG)
        for f in result.findings:
            assert f.remediation, f"{f.check_id} finding missing remediation text"

    def test_configs_scanned_count(self) -> None:
        result = scan_config(E2E_CONFIG)
        assert result.configs_scanned == 1
        assert result.config_path == E2E_CONFIG


class TestCLIOutputFormats:
    """Verify all three output formats work end-to-end."""

    def test_table_output_exits_one(self) -> None:
        result = runner.invoke(app, ["scan", "--config", str(E2E_CONFIG)])
        assert result.exit_code == 1
        # Rich table truncates columns; check for key content
        assert "Plaintext secrets" in result.output or "secrets-in" in result.output
        assert "finding(s)" in result.output

    def test_json_output_structure(self) -> None:
        result = runner.invoke(app, ["scan", "--config", str(E2E_CONFIG), "--output", "json"])
        assert result.exit_code == 1
        findings = json.loads(result.output)
        assert isinstance(findings, list)
        assert len(findings) >= 8

        # Verify JSON structure
        for f in findings:
            assert "check_id" in f
            assert "severity" in f
            assert "server_name" in f
            assert "remediation" in f

    def test_sarif_output_structure(self) -> None:
        result = runner.invoke(app, ["scan", "--config", str(E2E_CONFIG), "--output", "sarif"])
        assert result.exit_code == 1
        sarif = json.loads(result.output)

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) >= 8

        # Verify rule definitions exist
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert "MCP001" in rule_ids
        assert "MCP003" in rule_ids

    def test_sarif_output_to_file(self, tmp_path: Path) -> None:
        out = tmp_path / "report.sarif"
        result = runner.invoke(
            app,
            [
                "scan",
                "--config",
                str(E2E_CONFIG),
                "--output",
                "sarif",
                "--output-file",
                str(out),
            ],
        )
        assert result.exit_code == 1
        assert out.exists()
        sarif = json.loads(out.read_text())
        assert sarif["version"] == "2.1.0"


class TestCLISeverityFiltering:
    """Verify --min-severity and --fail-on work with real multi-severity findings."""

    def test_min_severity_filters_low_findings(self) -> None:
        result = runner.invoke(
            app,
            ["scan", "--config", str(E2E_CONFIG), "--output", "json", "--min-severity", "HIGH"],
        )
        findings = json.loads(result.output)
        for f in findings:
            assert f["severity"] in ("CRITICAL", "HIGH")

    def test_min_severity_critical_only(self) -> None:
        result = runner.invoke(
            app,
            [
                "scan",
                "--config",
                str(E2E_CONFIG),
                "--output",
                "json",
                "--min-severity",
                "CRITICAL",
            ],
        )
        findings = json.loads(result.output)
        for f in findings:
            assert f["severity"] == "CRITICAL"

    def test_fail_on_medium_exits_one(self) -> None:
        result = runner.invoke(app, ["scan", "--config", str(E2E_CONFIG), "--fail-on", "MEDIUM"])
        assert result.exit_code == 1

    def test_file_permissions_check_on_fixture(self) -> None:
        """MCP009 fires when the config file is world-readable."""
        os.chmod(E2E_CONFIG, 0o644)
        try:
            result = scan_config(E2E_CONFIG)
            check_ids = {f.check_id for f in result.findings}
            assert "MCP009" in check_ids, "MCP009 (world-readable) not triggered on 0o644"
        finally:
            os.chmod(E2E_CONFIG, 0o644)

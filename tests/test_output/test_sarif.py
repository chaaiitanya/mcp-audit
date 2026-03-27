"""Tests for SARIF output formatter."""

import json

from mcp_audit.checks.base import Finding, Severity
from mcp_audit.output.sarif import build_sarif


class TestSARIF:
    def _sample_finding(self) -> Finding:
        return Finding(
            check_id="MCP001",
            severity=Severity.CRITICAL,
            title="Plaintext secrets in env",
            description="OpenAI key detected in env var 'API_KEY'",
            server_name="test-server",
            remediation="Use ${VAR} references",
            evidence="env.API_KEY = sk-...",
        )

    def test_empty_findings(self):
        result = json.loads(build_sarif([]))
        assert result["version"] == "2.1.0"
        assert result["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert result["runs"][0]["results"] == []

    def test_findings_produce_results(self):
        result = json.loads(build_sarif([self._sample_finding()]))
        assert len(result["runs"][0]["results"]) == 1
        assert result["runs"][0]["results"][0]["ruleId"] == "MCP001"
        assert result["runs"][0]["results"][0]["level"] == "error"

    def test_severity_mapping(self):
        findings = [
            Finding("MCP001", Severity.CRITICAL, "t", "d", "s", "r"),
            Finding("MCP008", Severity.MEDIUM, "t", "d", "s", "r"),
            Finding("MCP010", Severity.LOW, "t", "d", "s", "r"),
        ]
        result = json.loads(build_sarif(findings))
        levels = [r["level"] for r in result["runs"][0]["results"]]
        assert levels == ["error", "warning", "note"]

    def test_rules_deduplicated(self):
        f1 = self._sample_finding()
        f2 = self._sample_finding()
        f2.description = "Another finding"
        result = json.loads(build_sarif([f1, f2]))
        rules = result["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1

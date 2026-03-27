"""Tests for JSON output formatter."""

import json

from mcp_audit.checks.base import Finding, Severity
from mcp_audit.output.json_output import build_json


class TestJSONOutput:
    def test_empty_findings(self):
        assert json.loads(build_json([])) == []

    def test_finding_serialized(self):
        finding = Finding("MCP001", Severity.CRITICAL, "title", "desc", "srv", "fix", "ev")
        result = json.loads(build_json([finding]))
        assert len(result) == 1
        assert result[0]["check_id"] == "MCP001"
        assert result[0]["severity"] == "CRITICAL"

    def test_multiple_findings(self):
        findings = [
            Finding("MCP001", Severity.CRITICAL, "t1", "d1", "s1", "r1"),
            Finding("MCP003", Severity.CRITICAL, "t2", "d2", "s2", "r2"),
        ]
        result = json.loads(build_json(findings))
        assert len(result) == 2

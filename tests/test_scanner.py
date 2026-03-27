"""Tests for the scanner module."""

from unittest.mock import patch

from mcp_audit.scanner import scan_discovery


class TestScanDiscovery:
    def test_discovery_with_configs(self, make_config_path):
        path = make_config_path({"srv": {"command": "node", "autoApprove": "*"}})
        with patch("mcp_audit.config.discovery.discover_configs", return_value=[path]):
            result = scan_discovery()
        assert result.configs_scanned == 1
        assert len(result.findings) >= 1

    def test_discovery_no_configs(self):
        with patch("mcp_audit.config.discovery.discover_configs", return_value=[]):
            result = scan_discovery()
        assert result.configs_scanned == 0
        assert result.findings == []

    def test_discovery_multiple_configs(self, make_config_path, tmp_path):
        p1 = make_config_path({"s1": {"command": "node", "autoApprove": "*"}}, "a.json")
        p2 = make_config_path({"s2": {"command": "node", "autoApprove": "*"}}, "b.json")
        with patch("mcp_audit.config.discovery.discover_configs", return_value=[p1, p2]):
            result = scan_discovery()
        assert result.configs_scanned == 2
        assert len(result.findings) >= 2

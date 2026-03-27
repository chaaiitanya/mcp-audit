"""Tests for the check registry."""

from mcp_audit.checks.registry import get_all_checks, get_registry


class TestRegistry:
    def test_get_registry_returns_all_checks(self):
        get_all_checks()  # trigger side-effect import
        registry = get_registry()
        assert len(registry) == 12
        assert "MCP001" in registry
        assert "MCP012" in registry

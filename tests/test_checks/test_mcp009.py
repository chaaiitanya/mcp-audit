"""Tests for MCP009: World-readable config file."""

import os
import sys

import pytest

from mcp_audit.checks.builtin.mcp009_file_permissions import WorldReadableConfigCheck
from mcp_audit.config.loader import load_config


class TestWorldReadableConfig:
    def setup_method(self):
        self.check = WorldReadableConfigCheck()

    def test_no_source_path(self, make_config):
        config = make_config({"srv": {"command": "node"}})
        config.source_path = None
        assert self.check.run(config) == []

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions only")
    def test_world_readable_flagged(self, make_config_path):
        path = make_config_path({"srv": {"command": "node"}})
        os.chmod(path, 0o644)
        config = load_config(path)
        findings = self.check.run(config)
        assert len(findings) == 1
        assert findings[0].check_id == "MCP009"
        assert findings[0].server_name == "(config file)"

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions only")
    def test_private_file_ok(self, make_config_path):
        path = make_config_path({"srv": {"command": "node"}})
        os.chmod(path, 0o600)
        config = load_config(path)
        assert self.check.run(config) == []

"""Shared pytest fixtures for mcp-audit tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mcp_audit.config.loader import load_config
from mcp_audit.config.models import MCPConfig


@pytest.fixture()
def make_config(tmp_path: Path):
    """Factory fixture: writes a config JSON and returns the loaded MCPConfig."""

    def _make(
        servers: dict[str, Any],
        filename: str = "mcp.json",
    ) -> MCPConfig:
        data = {"mcpServers": servers}
        p = tmp_path / filename
        p.write_text(json.dumps(data), encoding="utf-8")
        return load_config(p)

    return _make


@pytest.fixture()
def make_config_path(tmp_path: Path):
    """Factory fixture: writes a config JSON and returns the Path."""

    def _make(
        servers: dict[str, Any],
        filename: str = "mcp.json",
    ) -> Path:
        data = {"mcpServers": servers}
        p = tmp_path / filename
        p.write_text(json.dumps(data), encoding="utf-8")
        return p

    return _make


@pytest.fixture()
def clean_config(make_config: Any) -> MCPConfig:
    """A minimal clean config with no security issues."""
    return make_config(
        {
            "test-server": {
                "command": "node",
                "args": ["server.js"],
                "env": {"PORT": "3000"},
            }
        }
    )

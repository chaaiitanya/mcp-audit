"""Tests for config auto-discovery."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mcp_audit.config.discovery import discover_configs


class TestDiscoverConfigs:
    def test_returns_only_existing_paths(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Only paths that exist on disk are returned."""
        monkeypatch.setattr("mcp_audit.config.discovery.Path.home", lambda: tmp_path)
        monkeypatch.setattr("mcp_audit.config.discovery.Path.cwd", lambda: tmp_path)
        # Create one valid config
        mcp_json = tmp_path / ".mcp.json"
        mcp_json.write_text('{"mcpServers": {}}')

        results = discover_configs()
        assert mcp_json in results
        # Non-existent paths should not be included
        for p in results:
            assert p.exists()

    def test_empty_when_no_files_exist(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Returns empty list when no config files exist."""
        monkeypatch.setattr("mcp_audit.config.discovery.Path.home", lambda: tmp_path)
        monkeypatch.setattr("mcp_audit.config.discovery.Path.cwd", lambda: tmp_path)
        # Ensure no platform-specific paths match
        monkeypatch.setattr("mcp_audit.config.discovery.sys.platform", "linux")
        monkeypatch.delenv("APPDATA", raising=False)

        results = discover_configs()
        assert results == []

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only test")
    def test_claude_desktop_mac_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Claude Desktop macOS path is discovered when it exists."""
        monkeypatch.setattr("mcp_audit.config.discovery.Path.home", lambda: tmp_path)
        monkeypatch.setattr("mcp_audit.config.discovery.Path.cwd", lambda: tmp_path)

        claude_dir = tmp_path / "Library" / "Application Support" / "Claude"
        claude_dir.mkdir(parents=True)
        config = claude_dir / "claude_desktop_config.json"
        config.write_text('{"mcpServers": {}}')

        results = discover_configs()
        assert config in results

    def test_claude_code_paths(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Claude Code .mcp.json and ~/.claude.json are discovered."""
        monkeypatch.setattr("mcp_audit.config.discovery.Path.home", lambda: tmp_path)
        monkeypatch.setattr("mcp_audit.config.discovery.Path.cwd", lambda: tmp_path)
        monkeypatch.setattr("mcp_audit.config.discovery.sys.platform", "linux")

        mcp = tmp_path / ".mcp.json"
        mcp.write_text('{"mcpServers": {}}')
        claude = tmp_path / ".claude.json"
        claude.write_text('{"mcpServers": {}}')

        results = discover_configs()
        assert mcp in results
        assert claude in results

    def test_cursor_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Cursor config is discovered when it exists."""
        monkeypatch.setattr("mcp_audit.config.discovery.Path.home", lambda: tmp_path)
        monkeypatch.setattr("mcp_audit.config.discovery.Path.cwd", lambda: tmp_path)
        monkeypatch.setattr("mcp_audit.config.discovery.sys.platform", "linux")

        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        config = cursor_dir / "mcp.json"
        config.write_text('{"mcpServers": {}}')

        results = discover_configs()
        assert config in results

    def test_vscode_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """VS Code .vscode/mcp.json is discovered when it exists."""
        monkeypatch.setattr("mcp_audit.config.discovery.Path.home", lambda: tmp_path)
        monkeypatch.setattr("mcp_audit.config.discovery.Path.cwd", lambda: tmp_path)
        monkeypatch.setattr("mcp_audit.config.discovery.sys.platform", "linux")

        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        config = vscode_dir / "mcp.json"
        config.write_text('{"mcpServers": {}}')

        results = discover_configs()
        assert config in results

    def test_win32_appdata_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Windows APPDATA path is checked when platform is win32."""
        monkeypatch.setattr("mcp_audit.config.discovery.Path.home", lambda: tmp_path)
        monkeypatch.setattr("mcp_audit.config.discovery.Path.cwd", lambda: tmp_path)
        monkeypatch.setattr("mcp_audit.config.discovery.sys.platform", "win32")

        appdata = tmp_path / "AppData"
        claude_dir = appdata / "Claude"
        claude_dir.mkdir(parents=True)
        config = claude_dir / "claude_desktop_config.json"
        config.write_text('{"mcpServers": {}}')
        monkeypatch.setenv("APPDATA", str(appdata))

        results = discover_configs()
        assert config in results

    def test_win32_no_appdata(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """No crash when APPDATA is unset on win32."""
        monkeypatch.setattr("mcp_audit.config.discovery.Path.home", lambda: tmp_path)
        monkeypatch.setattr("mcp_audit.config.discovery.Path.cwd", lambda: tmp_path)
        monkeypatch.setattr("mcp_audit.config.discovery.sys.platform", "win32")
        monkeypatch.delenv("APPDATA", raising=False)

        # Should not crash
        results = discover_configs()
        assert isinstance(results, list)

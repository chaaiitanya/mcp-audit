"""Auto-discover MCP configuration files across supported clients."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def discover_configs() -> list[Path]:
    """Return paths to all MCP config files that exist on disk."""
    candidates: list[Path] = []

    # Claude Desktop
    if sys.platform == "darwin":
        candidates.append(
            Path.home()
            / "Library"
            / "Application Support"
            / "Claude"
            / "claude_desktop_config.json"
        )
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            candidates.append(Path(appdata) / "Claude" / "claude_desktop_config.json")

    # Claude Code
    candidates.append(Path.cwd() / ".mcp.json")
    candidates.append(Path.home() / ".claude.json")

    # Cursor
    candidates.append(Path.home() / ".cursor" / "mcp.json")

    # VS Code
    candidates.append(Path.cwd() / ".vscode" / "mcp.json")

    return [p for p in candidates if p.exists()]

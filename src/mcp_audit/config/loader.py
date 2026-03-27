"""Load and parse MCP configuration files."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_audit.config.models import MCPConfig


class ConfigParseError(Exception):
    """Raised when a configuration file cannot be parsed."""

    def __init__(self, path: Path, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"Failed to parse {path}: {reason}")


def load_config(path: Path) -> MCPConfig:
    """Load an MCP config from a JSON file path.

    Raises:
        ConfigParseError: If the file cannot be read or parsed.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigParseError(path, "File not found") from exc
    except OSError as exc:
        raise ConfigParseError(path, str(exc)) from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigParseError(path, f"Invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigParseError(path, "Expected a JSON object at root")

    try:
        config = MCPConfig.model_validate(data)
    except Exception as exc:
        raise ConfigParseError(path, str(exc)) from exc

    config.source_path = path
    return config


def load_all(paths: list[Path]) -> tuple[list[MCPConfig], list[ConfigParseError]]:
    """Load multiple config files, collecting errors instead of raising."""
    configs: list[MCPConfig] = []
    errors: list[ConfigParseError] = []
    for path in paths:
        try:
            configs.append(load_config(path))
        except ConfigParseError as exc:
            errors.append(exc)
    return configs, errors

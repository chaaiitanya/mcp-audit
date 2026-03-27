"""Pydantic v2 models for MCP server configurations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class MCPServerConfig(BaseModel):
    """Configuration for a single MCP server entry."""

    model_config = ConfigDict(extra="allow")

    command: str = ""
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    autoApprove: list[str | bool] = Field(default_factory=list)
    url: str | None = None

    @field_validator("autoApprove", mode="before")
    @classmethod
    def normalize_auto_approve(cls, v: Any) -> list[str | bool]:
        """Normalize autoApprove to always be a list."""
        if isinstance(v, (str, bool)):
            return [v]
        if v is None:
            return []
        return list(v)


class MCPConfig(BaseModel):
    """Top-level MCP configuration file model."""

    model_config = ConfigDict(extra="allow")

    mcpServers: dict[str, MCPServerConfig] = Field(default_factory=dict)
    source_path: Path | None = Field(default=None, exclude=True)

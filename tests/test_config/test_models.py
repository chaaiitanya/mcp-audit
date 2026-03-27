"""Tests for config models."""

from pathlib import Path

from mcp_audit.config.models import MCPConfig, MCPServerConfig


class TestMCPServerConfig:
    def test_defaults(self):
        server = MCPServerConfig()
        assert server.command == ""
        assert server.args == []
        assert server.env == {}
        assert server.autoApprove == []
        assert server.url is None

    def test_auto_approve_string_normalized(self):
        server = MCPServerConfig(autoApprove="*")
        assert server.autoApprove == ["*"]

    def test_auto_approve_bool_normalized(self):
        server = MCPServerConfig(autoApprove=True)
        assert server.autoApprove == [True]

    def test_extra_fields_preserved(self):
        server = MCPServerConfig(command="node", tools=[{"name": "test"}])
        assert server.model_extra["tools"] == [{"name": "test"}]


class TestMCPConfig:
    def test_defaults(self):
        config = MCPConfig()
        assert config.mcpServers == {}
        assert config.source_path is None

    def test_parse_from_dict(self):
        data = {
            "mcpServers": {
                "test": {"command": "node", "args": ["server.js"]},
            }
        }
        config = MCPConfig.model_validate(data)
        assert "test" in config.mcpServers
        assert config.mcpServers["test"].command == "node"

    def test_source_path_excluded_from_json(self):
        config = MCPConfig(source_path=Path("/tmp/test.json"))
        dumped = config.model_dump()
        assert "source_path" not in dumped

    def test_extra_fields_preserved(self):
        config = MCPConfig.model_validate({"mcpServers": {}, "customField": "value"})
        assert config.model_extra["customField"] == "value"

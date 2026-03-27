"""Tests for config loader."""

import pytest

from mcp_audit.config.loader import ConfigParseError, load_all, load_config


class TestLoadConfig:
    def test_valid_config(self, make_config_path):
        path = make_config_path({"srv": {"command": "node"}})
        config = load_config(path)
        assert "srv" in config.mcpServers
        assert config.source_path == path

    def test_file_not_found(self, tmp_path):
        with pytest.raises(ConfigParseError, match="File not found"):
            load_config(tmp_path / "nonexistent.json")

    def test_invalid_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("not json!")
        with pytest.raises(ConfigParseError, match="Invalid JSON"):
            load_config(p)

    def test_not_a_dict(self, tmp_path):
        p = tmp_path / "array.json"
        p.write_text("[1,2,3]")
        with pytest.raises(ConfigParseError, match="Expected a JSON object"):
            load_config(p)

    def test_os_error_raises_config_parse_error(self, tmp_path):
        p = tmp_path / "unreadable.json"
        p.write_text("{}")
        p.chmod(0o000)
        with pytest.raises(ConfigParseError):
            load_config(p)
        p.chmod(0o644)  # restore for cleanup

    def test_pydantic_validation_error(self, tmp_path):
        """JSON that is a valid dict but fails Pydantic validation."""
        p = tmp_path / "bad_types.json"
        p.write_text('{"mcpServers": "not_a_dict"}')
        with pytest.raises(ConfigParseError):
            load_config(p)


class TestLoadAll:
    def test_collects_configs_and_errors(self, make_config_path, tmp_path):
        good = make_config_path({"srv": {"command": "node"}}, "good.json")
        bad = tmp_path / "bad.json"
        bad.write_text("not json")

        configs, errors = load_all([good, bad])
        assert len(configs) == 1
        assert len(errors) == 1

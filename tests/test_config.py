import json
import os
import tempfile
from pathlib import Path

import pytest

from extensible_mcp.config import Config, find_config_path, load_config


def _write_config(tmp: str, data: dict) -> Path:
    path = Path(tmp) / "config.json"
    path.write_text(json.dumps(data))
    return path


@pytest.fixture
def valid_config_data():
    return {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            },
            "github": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "env": {"GITHUB_TOKEN": "test"},
            },
        },
        "filters": {
            "similarity_threshold": 0.4,
            "access_control": {
                "deny": ["github__delete_repo"],
                "deny_patterns": ["*__drop_*"],
                "allow_servers": ["filesystem"],
            },
        },
    }


class TestLoadConfig:
    def test_loads_valid_config(self, valid_config_data):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, valid_config_data)
            config = load_config(path)
            assert len(config.servers) == 2
            assert config.servers[0].name == "filesystem"
            assert config.servers[1].name == "github"
            assert config.servers[1].env == {"GITHUB_TOKEN": "test"}
            assert config.filters.similarity_threshold == 0.4
            assert "github__delete_repo" in config.filters.access_control.deny

    def test_minimal_config(self):
        data = {"mcpServers": {"test": {"command": "echo"}}}
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, data)
            config = load_config(path)
            assert len(config.servers) == 1
            assert config.filters.similarity_threshold == 0.3

    def test_rejects_empty_servers(self):
        data = {"mcpServers": {}}
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, data)
            with pytest.raises(ValueError, match="at least one server"):
                load_config(path)

    def test_rejects_missing_command(self):
        data = {"mcpServers": {"bad": {"args": ["test"]}}}
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, data)
            with pytest.raises(ValueError, match="command"):
                load_config(path)


class TestFindConfigPath:
    def test_cli_arg(self):
        with tempfile.NamedTemporaryFile(suffix=".json") as f:
            assert find_config_path(f.name) == Path(f.name)

    def test_cli_arg_missing(self):
        with pytest.raises(FileNotFoundError):
            find_config_path("/nonexistent/config.json")

    def test_env_var(self, monkeypatch):
        with tempfile.NamedTemporaryFile(suffix=".json") as f:
            monkeypatch.setenv("EXTENSIBLE_MCP_CONFIG", f.name)
            assert find_config_path() == Path(f.name)

    def test_env_var_missing(self, monkeypatch):
        monkeypatch.setenv("EXTENSIBLE_MCP_CONFIG", "/nonexistent.json")
        with pytest.raises(FileNotFoundError):
            find_config_path()

    def test_no_config_found(self, monkeypatch, tmp_path):
        monkeypatch.delenv("EXTENSIBLE_MCP_CONFIG", raising=False)
        monkeypatch.chdir(tmp_path)
        with pytest.raises(FileNotFoundError):
            find_config_path()

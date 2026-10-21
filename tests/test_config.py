# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

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

    def test_rejects_missing_command_and_url(self):
        data = {"mcpServers": {"bad": {"args": ["test"]}}}
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, data)
            with pytest.raises(ValueError, match="command.*or.*url"):
                load_config(path)

    def test_loads_url_server(self):
        data = {"mcpServers": {"remote": {"url": "https://example.com/mcp"}}}
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, data)
            config = load_config(path)
            assert len(config.servers) == 1
            assert config.servers[0].url == "https://example.com/mcp"
            assert config.servers[0].command is None

    def test_loads_mixed_servers(self):
        data = {
            "mcpServers": {
                "local": {"command": "echo"},
                "remote": {"url": "https://example.com/mcp"},
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, data)
            config = load_config(path)
            assert len(config.servers) == 2
            assert config.servers[0].command == "echo"
            assert config.servers[1].url == "https://example.com/mcp"

    def test_rejects_both_command_and_url(self):
        data = {"mcpServers": {"bad": {"command": "echo", "url": "https://example.com"}}}
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, data)
            with pytest.raises(ValueError, match="not both"):
                load_config(path)


class TestTokensFileResolution:
    def test_default_picks_up_tokens_next_to_config(self, monkeypatch):
        monkeypatch.delenv("EXTENSIBLE_MCP_TOKENS_FILE", raising=False)
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, {"mcpServers": {"test": {"command": "echo"}}})
            (Path(tmp) / "tokens").write_text("foo=bar\n")
            config = load_config(path)
            assert config.tokens_file == Path(tmp) / "tokens"

    def test_default_yields_none_when_no_tokens_file(self, monkeypatch):
        monkeypatch.delenv("EXTENSIBLE_MCP_TOKENS_FILE", raising=False)
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, {"mcpServers": {"test": {"command": "echo"}}})
            config = load_config(path)
            assert config.tokens_file is None

    def test_env_var_overrides_default(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, {"mcpServers": {"test": {"command": "echo"}}})
            (Path(tmp) / "tokens").write_text("ignored=value\n")
            elsewhere = Path(tmp) / "elsewhere-tokens"
            elsewhere.write_text("real=value\n")
            monkeypatch.setenv("EXTENSIBLE_MCP_TOKENS_FILE", str(elsewhere))
            config = load_config(path)
            assert config.tokens_file == elsewhere

    def test_env_var_relative_resolves_to_config_dir(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, {"mcpServers": {"test": {"command": "echo"}}})
            (Path(tmp) / "my-tokens").write_text("a=b\n")
            monkeypatch.setenv("EXTENSIBLE_MCP_TOKENS_FILE", "my-tokens")
            config = load_config(path)
            assert config.tokens_file == Path(tmp) / "my-tokens"

    def test_env_var_expands_tilde(self, monkeypatch, tmp_path):
        token_file = tmp_path / "expanded-tokens"
        token_file.write_text("a=b\n")
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("EXTENSIBLE_MCP_TOKENS_FILE", "~/expanded-tokens")
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, {"mcpServers": {"test": {"command": "echo"}}})
            config = load_config(path)
            assert config.tokens_file == token_file

    def test_env_var_pointing_at_missing_file_raises(self, monkeypatch):
        monkeypatch.setenv("EXTENSIBLE_MCP_TOKENS_FILE", "/nonexistent/tokens")
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, {"mcpServers": {"test": {"command": "echo"}}})
            with pytest.raises(FileNotFoundError, match="EXTENSIBLE_MCP_TOKENS_FILE"):
                load_config(path)

    def test_dotenv_provides_path_when_env_unset(self, monkeypatch):
        monkeypatch.delenv("EXTENSIBLE_MCP_TOKENS_FILE", raising=False)
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, {"mcpServers": {"test": {"command": "echo"}}})
            target = Path(tmp) / "from-dotenv-tokens"
            target.write_text("a=b\n")
            (Path(tmp) / ".env").write_text(f"EXTENSIBLE_MCP_TOKENS_FILE={target}\n")
            config = load_config(path)
            assert config.tokens_file == target


class TestCredentialsBlock:
    """The ``credentials`` block: named OAuth client identities, referenced
    per server, with no field anywhere for a secret."""

    @pytest.fixture(autouse=True)
    def _no_ambient_tokens_file(self, monkeypatch):
        monkeypatch.delenv("EXTENSIBLE_MCP_TOKENS_FILE", raising=False)

    def test_parses_named_credentials_referenced_per_server(self, tmp_path):
        path = _write_config(
            str(tmp_path),
            {
                "credentials": {
                    "corp-as": {
                        "grant": "private_key_jwt",
                        "token_endpoint": "https://as.example.com/oauth/token",
                        "client_id": "extensible-mcp-proxy",
                        "private_key_file": "keys/proxy-signing.pem",
                    },
                    "legacy-as": {
                        "grant": "client_credentials",
                        "token_endpoint": "https://legacy.example.com/oauth/token",
                        "client_id": "extensible-mcp-proxy",
                        "client_secret_env": "LEGACY_CLIENT_SECRET",
                    },
                },
                "mcpServers": {
                    "payments": {
                        "url": "https://payments.example.com/mcp",
                        "credential": "corp-as",
                        "scope": "payments.invoke",
                        "audience": "https://payments.example.com",
                    },
                    "filesystem": {"command": "npx", "args": ["-y", "x"]},
                },
            },
        )
        config = load_config(path)

        assert sorted(config.credentials) == ["corp-as", "legacy-as"]
        corp = config.credentials["corp-as"]
        assert corp.grant == "private_key_jwt"
        assert corp.token_endpoint == "https://as.example.com/oauth/token"
        assert corp.client_id == "extensible-mcp-proxy"
        assert corp.client_secret_env is None
        legacy = config.credentials["legacy-as"]
        assert legacy.client_secret_env == "LEGACY_CLIENT_SECRET"
        assert legacy.private_key_file is None

        payments = next(s for s in config.servers if s.name == "payments")
        assert payments.credential == "corp-as"
        assert payments.scope == "payments.invoke"
        assert payments.audience == "https://payments.example.com"
        filesystem = next(s for s in config.servers if s.name == "filesystem")
        assert filesystem.credential is None

    def test_an_inline_client_secret_is_refused_at_load(self, tmp_path):
        """config.json is committed and shared, so the secret is named, not
        carried. The message has to say where to put it instead."""
        path = _write_config(
            str(tmp_path),
            {
                "credentials": {
                    "legacy-as": {
                        "grant": "client_credentials",
                        "token_endpoint": "https://legacy.example.com/oauth/token",
                        "client_id": "extensible-mcp-proxy",
                        "client_secret": "hunter2",
                    }
                },
                "mcpServers": {"test": {"command": "echo"}},
            },
        )
        with pytest.raises(ValueError, match="client_secret_env") as info:
            load_config(path)
        assert "inline 'client_secret'" in str(info.value)

    def test_a_relative_private_key_file_resolves_against_the_config_dir(
        self, tmp_path
    ):
        path = _write_config(
            str(tmp_path),
            {
                "credentials": {
                    "corp-as": {
                        "grant": "private_key_jwt",
                        "token_endpoint": "https://as.example.com/oauth/token",
                        "client_id": "proxy",
                        "private_key_file": "keys/proxy-signing.pem",
                    }
                },
                "mcpServers": {"test": {"command": "echo"}},
            },
        )
        config = load_config(path)
        assert config.credentials["corp-as"].private_key_file == (
            tmp_path / "keys" / "proxy-signing.pem"
        )

    def test_an_absolute_private_key_file_is_left_alone(self, tmp_path):
        absolute = tmp_path / "elsewhere" / "signing.pem"
        path = _write_config(
            str(tmp_path),
            {
                "credentials": {
                    "corp-as": {
                        "grant": "private_key_jwt",
                        "token_endpoint": "https://as.example.com/oauth/token",
                        "client_id": "proxy",
                        "private_key_file": str(absolute),
                    }
                },
                "mcpServers": {"test": {"command": "echo"}},
            },
        )
        assert load_config(path).credentials["corp-as"].private_key_file == absolute

    def test_a_server_naming_an_undefined_credential_is_refused(self, tmp_path):
        path = _write_config(
            str(tmp_path),
            {
                "mcpServers": {
                    "payments": {
                        "url": "https://payments.example.com/mcp",
                        "credential": "corp-as",
                    }
                }
            },
        )
        with pytest.raises(ValueError, match="not defined in 'credentials'"):
            load_config(path)

    def test_an_unsupported_grant_is_refused(self, tmp_path):
        """Including a grant a later version might add: presenting the wrong
        credential is worse than refusing to start."""
        path = _write_config(
            str(tmp_path),
            {
                "credentials": {
                    "k8s": {
                        "grant": "workload_identity",
                        "token_endpoint": "https://as.example.com/oauth/token",
                        "client_id": "proxy",
                    }
                },
                "mcpServers": {"test": {"command": "echo"}},
            },
        )
        with pytest.raises(ValueError, match="unsupported grant"):
            load_config(path)

    @pytest.mark.parametrize(
        "entry,expected",
        [
            (
                {
                    "grant": "private_key_jwt",
                    "token_endpoint": "https://as/token",
                    "client_id": "proxy",
                },
                "private_key_file",
            ),
            (
                {
                    "grant": "client_credentials",
                    "token_endpoint": "https://as/token",
                    "client_id": "proxy",
                },
                "client_secret_env",
            ),
            (
                {"token_endpoint": "https://as/token", "client_id": "proxy"},
                "'grant' field",
            ),
            (
                {"grant": "client_credentials", "client_id": "proxy"},
                "'token_endpoint' field",
            ),
            (
                {
                    "grant": "client_credentials",
                    "token_endpoint": "https://as/token",
                    "client_secret_env": "S",
                },
                "'client_id' field",
            ),
            (
                {
                    "grant": "private_key_jwt",
                    "token_endpoint": "https://as/token",
                    "client_id": "proxy",
                    "private_key_file": "k.pem",
                    "client_secret_env": "S",
                },
                "unexpected field",
            ),
        ],
    )
    def test_an_incomplete_or_mixed_up_credential_is_refused(
        self, tmp_path, entry, expected
    ):
        path = _write_config(
            str(tmp_path),
            {
                "credentials": {"c": entry},
                "mcpServers": {"test": {"command": "echo"}},
            },
        )
        with pytest.raises(ValueError, match=expected):
            load_config(path)

    def test_a_credential_and_a_tokens_entry_for_one_server_is_refused(
        self, tmp_path
    ):
        """Both configured is ambiguous, and a precedence rule would pick one
        credential silently."""
        (tmp_path / "tokens").write_text("payments=long-lived-bearer\n")
        path = _write_config(
            str(tmp_path),
            {
                "credentials": {
                    "corp-as": {
                        "grant": "client_credentials",
                        "token_endpoint": "https://as.example.com/oauth/token",
                        "client_id": "proxy",
                        "client_secret_env": "SECRET",
                    }
                },
                "mcpServers": {
                    "payments": {
                        "url": "https://payments.example.com/mcp",
                        "credential": "corp-as",
                    }
                },
            },
        )
        with pytest.raises(ValueError, match="also has an entry in the tokens file"):
            load_config(path)

    def test_a_tokens_entry_for_a_different_server_is_fine(self, tmp_path):
        """A deployment migrating one server at a time has to keep working."""
        (tmp_path / "tokens").write_text("legacy=long-lived-bearer\n")
        path = _write_config(
            str(tmp_path),
            {
                "credentials": {
                    "corp-as": {
                        "grant": "client_credentials",
                        "token_endpoint": "https://as.example.com/oauth/token",
                        "client_id": "proxy",
                        "client_secret_env": "SECRET",
                    }
                },
                "mcpServers": {
                    "payments": {
                        "url": "https://payments.example.com/mcp",
                        "credential": "corp-as",
                    },
                    "legacy": {"url": "https://legacy.example.com/mcp"},
                },
            },
        )
        config = load_config(path)
        assert config.tokens_file == tmp_path / "tokens"
        assert {s.name: s.credential for s in config.servers} == {
            "payments": "corp-as",
            "legacy": None,
        }

    def test_a_credential_on_a_stdio_server_is_refused(self, tmp_path):
        """It could never be presented, so accepting it would look configured
        and do nothing."""
        path = _write_config(
            str(tmp_path),
            {
                "credentials": {
                    "corp-as": {
                        "grant": "client_credentials",
                        "token_endpoint": "https://as.example.com/oauth/token",
                        "client_id": "proxy",
                        "client_secret_env": "SECRET",
                    }
                },
                "mcpServers": {"local": {"command": "echo", "credential": "corp-as"}},
            },
        )
        with pytest.raises(ValueError, match="stdio server"):
            load_config(path)

    def test_scope_or_audience_without_a_credential_is_refused(self, tmp_path):
        """#25 pins the audience as a control; one that nothing uses must not
        read as though it were in force."""
        path = _write_config(
            str(tmp_path),
            {
                "mcpServers": {
                    "payments": {
                        "url": "https://payments.example.com/mcp",
                        "audience": "https://payments.example.com",
                    }
                }
            },
        )
        with pytest.raises(ValueError, match="names no 'credential'"):
            load_config(path)

    def test_credentials_must_be_an_object(self, tmp_path):
        path = _write_config(
            str(tmp_path),
            {"credentials": ["corp-as"], "mcpServers": {"test": {"command": "echo"}}},
        )
        with pytest.raises(ValueError, match="'credentials' must be an object"):
            load_config(path)

    def test_the_shipped_example_config_is_valid(self, tmp_path):
        """config.example.json is what an operator copies, so it has to load."""
        example = Path(__file__).parent.parent / "config.example.json"
        path = tmp_path / "config.json"
        path.write_text(example.read_text())

        config = load_config(path)

        assert config.credentials["corp-as"].grant == "private_key_jwt"
        assert config.credentials["legacy-as"].grant == "client_credentials"
        payments = next(s for s in config.servers if s.name == "payments")
        assert payments.credential == "corp-as"


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

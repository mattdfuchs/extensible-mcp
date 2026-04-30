# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .types import ServerConfig


@dataclass
class AccessControlConfig:
    deny: list[str] = field(default_factory=list)
    deny_patterns: list[str] = field(default_factory=list)
    allow_servers: list[str] = field(default_factory=list)


@dataclass
class LoadControlConfig:
    deny_names: list[str] = field(default_factory=list)
    deny_name_patterns: list[str] = field(default_factory=list)
    deny_url_patterns: list[str] = field(default_factory=list)
    allow_url_patterns: list[str] = field(default_factory=list)


@dataclass
class FiltersConfig:
    similarity_threshold: float = 0.3
    access_control: AccessControlConfig = field(default_factory=AccessControlConfig)
    rego_policy: str | None = None
    load_control: LoadControlConfig = field(default_factory=LoadControlConfig)


@dataclass
class Config:
    servers: list[ServerConfig] = field(default_factory=list)
    filters: FiltersConfig = field(default_factory=FiltersConfig)
    tokens_file: Optional[Path] = None


def _default_config_paths() -> list[Path]:
    paths = []
    if sys.platform == "darwin":
        paths.append(
            Path.home()
            / "Library"
            / "Application Support"
            / "extensible-mcp"
            / "config.json"
        )
    paths.append(Path.home() / ".config" / "extensible-mcp" / "config.json")
    paths.append(Path("config.json"))
    return paths


def find_config_path(cli_arg: str | None = None) -> Path:
    if cli_arg:
        path = Path(cli_arg)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        return path

    env_path = os.environ.get("EXTENSIBLE_MCP_CONFIG")
    if env_path:
        path = Path(env_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        return path

    for path in _default_config_paths():
        if path.exists():
            return path

    raise FileNotFoundError(
        "No config file found. Provide one via --config, "
        "EXTENSIBLE_MCP_CONFIG env var, or place config.json in the current directory."
    )


def _load_dotenv(config_dir: Path) -> dict[str, str]:
    """Load key=value pairs from a .env file next to the config, if it exists."""
    env_file = config_dir / ".env"
    if not env_file.exists():
        return {}
    values: dict[str, str] = {}
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        # Strip optional quotes
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[key.strip()] = value
    return values


def _resolve_env_values(
    env: dict[str, str] | None, dotenv: dict[str, str]
) -> dict[str, str] | None:
    """Expand $VAR references in env values using dotenv, then os.environ."""
    if not env:
        return env
    resolved: dict[str, str] = {}
    for key, value in env.items():
        if value.startswith("$"):
            var_name = value[1:]
            resolved[key] = dotenv.get(var_name, os.environ.get(var_name, value))
        else:
            resolved[key] = value
    return resolved


def load_config(path: Path) -> Config:
    with open(path) as f:
        raw: dict[str, Any] = json.load(f)

    dotenv = _load_dotenv(path.parent)

    servers: list[ServerConfig] = []
    for name, server_def in raw.get("mcpServers", {}).items():
        if not isinstance(server_def, dict):
            raise ValueError(f"Server '{name}' must be an object")
        if "command" not in server_def and "url" not in server_def:
            raise ValueError(f"Server '{name}' must have a 'command' or 'url' field")
        servers.append(
            ServerConfig(
                name=name,
                command=server_def.get("command"),
                args=server_def.get("args", []),
                env=_resolve_env_values(server_def.get("env"), dotenv),
                url=server_def.get("url"),
            )
        )

    filters_raw = raw.get("filters", {})
    ac_raw = filters_raw.get("access_control", {})
    access_control = AccessControlConfig(
        deny=ac_raw.get("deny", []),
        deny_patterns=ac_raw.get("deny_patterns", []),
        allow_servers=ac_raw.get("allow_servers", []),
    )
    lc_raw = filters_raw.get("load_control", {})
    load_control = LoadControlConfig(
        deny_names=lc_raw.get("deny_names", []),
        deny_name_patterns=lc_raw.get("deny_name_patterns", []),
        deny_url_patterns=lc_raw.get("deny_url_patterns", []),
        allow_url_patterns=lc_raw.get("allow_url_patterns", []),
    )
    rego_policy_raw = filters_raw.get("rego_policy")
    rego_policy: str | None = None
    if rego_policy_raw:
        rego_path = Path(rego_policy_raw)
        if not rego_path.is_absolute():
            rego_path = path.parent / rego_path
        rego_policy = str(rego_path)

    filters = FiltersConfig(
        similarity_threshold=filters_raw.get("similarity_threshold", 0.3),
        access_control=access_control,
        rego_policy=rego_policy,
        load_control=load_control,
    )

    if not servers:
        raise ValueError("Config must define at least one server in 'mcpServers'")

    tokens_path = path.parent / "tokens"
    tokens_file = tokens_path if tokens_path.exists() else None

    return Config(servers=servers, filters=filters, tokens_file=tokens_file)

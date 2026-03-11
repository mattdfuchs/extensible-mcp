from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .types import ServerConfig


@dataclass
class AccessControlConfig:
    deny: list[str] = field(default_factory=list)
    deny_patterns: list[str] = field(default_factory=list)
    allow_servers: list[str] = field(default_factory=list)


@dataclass
class FiltersConfig:
    similarity_threshold: float = 0.3
    access_control: AccessControlConfig = field(default_factory=AccessControlConfig)


@dataclass
class Config:
    servers: list[ServerConfig] = field(default_factory=list)
    filters: FiltersConfig = field(default_factory=FiltersConfig)


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


def load_config(path: Path) -> Config:
    with open(path) as f:
        raw: dict[str, Any] = json.load(f)

    servers: list[ServerConfig] = []
    for name, server_def in raw.get("mcpServers", {}).items():
        if not isinstance(server_def, dict) or "command" not in server_def:
            raise ValueError(f"Server '{name}' must have a 'command' field")
        servers.append(
            ServerConfig(
                name=name,
                command=server_def["command"],
                args=server_def.get("args", []),
                env=server_def.get("env"),
            )
        )

    filters_raw = raw.get("filters", {})
    ac_raw = filters_raw.get("access_control", {})
    access_control = AccessControlConfig(
        deny=ac_raw.get("deny", []),
        deny_patterns=ac_raw.get("deny_patterns", []),
        allow_servers=ac_raw.get("allow_servers", []),
    )
    filters = FiltersConfig(
        similarity_threshold=filters_raw.get("similarity_threshold", 0.3),
        access_control=access_control,
    )

    if not servers:
        raise ValueError("Config must define at least one server in 'mcpServers'")

    return Config(servers=servers, filters=filters)

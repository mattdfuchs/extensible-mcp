# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .credentials import (
    GRANT_CLIENT_CREDENTIALS,
    GRANT_PRIVATE_KEY_JWT,
    SUPPORTED_GRANTS,
)
from .types import CredentialConfig, ServerConfig


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
class PolicyBundleConfig:
    """A policy bundle declared in ``config.json`` for one server.

    The direct, declared form of what ``bundle_router`` decides at admission:
    this server's tools are governed by the bundle at ``path``, with
    ``config`` supplying the facts the fetch plan's ``config`` entries read.
    ``engine`` forces an engine where the directory carries more than one
    artifact; ``single_use`` names the credential fields to spend per call.
    """

    server: str
    path: Path
    config: dict[str, Any] = field(default_factory=dict)
    engine: str | None = None
    single_use: list[str] = field(default_factory=list)


@dataclass
class FiltersConfig:
    similarity_threshold: float = 0.3
    access_control: AccessControlConfig = field(default_factory=AccessControlConfig)
    rego_policy: str | None = None
    load_control: LoadControlConfig = field(default_factory=LoadControlConfig)
    policy_bundles: dict[str, PolicyBundleConfig] = field(default_factory=dict)


@dataclass
class Config:
    servers: list[ServerConfig] = field(default_factory=list)
    filters: FiltersConfig = field(default_factory=FiltersConfig)
    tokens_file: Optional[Path] = None
    credentials: dict[str, CredentialConfig] = field(default_factory=dict)


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


def read_tokens_file(path: Path) -> dict[str, str]:
    """Read ``server_name=token`` pairs from a tokens property file.

    Supported, and to be removed in a later release in favour of the grant
    path -- see
    ``credentials.py`` -- but still read: a deployment that has not migrated
    keeps working, and the loader needs to know which names have an entry so
    that a server with both a token and a grant can be refused.
    """
    if not path.exists():
        return {}
    tokens: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        tokens[key.strip()] = value
    return tokens


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


# Fields a credential may carry, per grant. Everything else is a typo, and a
# typo in a credential block is a deployment that looks configured and is not.
_COMMON_CREDENTIAL_KEYS = frozenset({"grant", "token_endpoint", "client_id"})
_GRANT_KEYS = {
    GRANT_PRIVATE_KEY_JWT: frozenset({"private_key_file"}),
    GRANT_CLIENT_CREDENTIALS: frozenset({"client_secret_env"}),
}


def _resolve_relative(value: str, config_dir: Path) -> Path:
    """Resolve a config-supplied path against the config file's parent.

    The same rule as ``filters.rego_policy``: a config file travels with the
    files it names.
    """
    resolved = Path(os.path.expanduser(value))
    if not resolved.is_absolute():
        resolved = config_dir / resolved
    return resolved


def _load_credentials(
    raw: dict[str, Any], config_dir: Path
) -> dict[str, CredentialConfig]:
    """Parse the ``credentials`` block, refusing anything ambiguous.

    Named credentials referenced per server, rather than an inline object,
    because one authorization server commonly fronts several downstream
    servers: repeating the block per server invites copy-paste divergence,
    and two spellings would mean two code paths.
    """
    credentials_raw = raw.get("credentials", {})
    if not isinstance(credentials_raw, dict):
        raise ValueError(
            "'credentials' must be an object mapping a credential name to its grant"
        )

    credentials: dict[str, CredentialConfig] = {}
    for name, entry in credentials_raw.items():
        if not isinstance(entry, dict):
            raise ValueError(f"Credential '{name}' must be an object")
        if "client_secret" in entry:
            # Deliberately not a supported field. config.json is a file people
            # commit and share, and the repo's secret-scanning job exists for
            # exactly this mistake.
            raise ValueError(
                f"Credential '{name}' carries an inline 'client_secret'. There is "
                "no such field: config.json is committed and shared. Put the "
                "secret in an environment variable and name that variable with "
                "'client_secret_env' instead."
            )
        grant = entry.get("grant")
        if not grant:
            raise ValueError(f"Credential '{name}' must have a 'grant' field")
        if grant not in SUPPORTED_GRANTS:
            raise ValueError(
                f"Credential '{name}' has unsupported grant '{grant}'; this build "
                f"implements {', '.join(SUPPORTED_GRANTS)}"
            )
        allowed = _COMMON_CREDENTIAL_KEYS | _GRANT_KEYS[grant]
        unknown = sorted(set(entry) - allowed)
        if unknown:
            raise ValueError(
                f"Credential '{name}' (grant '{grant}') has unexpected field(s) "
                f"{unknown}; it takes {sorted(allowed)}"
            )
        token_endpoint = entry.get("token_endpoint")
        if not token_endpoint:
            raise ValueError(f"Credential '{name}' must have a 'token_endpoint' field")
        client_id = entry.get("client_id")
        if not client_id:
            raise ValueError(f"Credential '{name}' must have a 'client_id' field")

        private_key_file: Path | None = None
        client_secret_env: str | None = None
        if grant == GRANT_PRIVATE_KEY_JWT:
            key_file = entry.get("private_key_file")
            if not key_file:
                raise ValueError(
                    f"Credential '{name}' uses the private_key_jwt grant, so it "
                    "must have a 'private_key_file' field"
                )
            private_key_file = _resolve_relative(key_file, config_dir)
        else:
            client_secret_env = entry.get("client_secret_env")
            if not client_secret_env:
                raise ValueError(
                    f"Credential '{name}' uses the client_credentials grant, so it "
                    "must have a 'client_secret_env' field naming the environment "
                    "variable that holds the secret"
                )

        credentials[name] = CredentialConfig(
            name=name,
            grant=grant,
            token_endpoint=token_endpoint,
            client_id=client_id,
            private_key_file=private_key_file,
            client_secret_env=client_secret_env,
        )
    return credentials


_POLICY_BUNDLE_KEYS = frozenset({"path", "config", "engine", "single_use"})
_POLICY_BUNDLE_ENGINES = ("rego", "cel", "cedar")


def _load_policy_bundles(
    raw: Any, *, base_dir: Path, server_names: set[str]
) -> dict[str, PolicyBundleConfig]:
    """Parse ``filters.policy_bundles``, refusing anything ambiguous.

    Keyed by server name so that a bundle governs a *server*, the same unit
    ``bundle_router`` governs; a name that is not in ``mcpServers`` is a typo
    that would otherwise leave a gate declared and never attached, which is
    the quiet failure this loader exists to refuse. Unknown keys are refused
    for the same reason: ``"singe_use"`` must not mean "no single use".
    """
    if not isinstance(raw, dict):
        raise ValueError(
            "'filters.policy_bundles' must be an object mapping a server name "
            "to its bundle"
        )
    bundles: dict[str, PolicyBundleConfig] = {}
    for server, entry in raw.items():
        if not isinstance(entry, dict):
            raise ValueError(f"Policy bundle for '{server}' must be an object")
        unknown = sorted(set(entry) - _POLICY_BUNDLE_KEYS)
        if unknown:
            raise ValueError(
                f"Policy bundle for '{server}' has unexpected field(s) {unknown}; "
                f"allowed: {sorted(_POLICY_BUNDLE_KEYS)}"
            )
        if server not in server_names:
            raise ValueError(
                f"Policy bundle for '{server}' names a server that is not in "
                f"'mcpServers' (defined: {sorted(server_names)})"
            )
        path_raw = entry.get("path")
        if not isinstance(path_raw, str) or not path_raw:
            raise ValueError(f"Policy bundle for '{server}' must have a 'path' field")
        bundle_path = Path(path_raw)
        if not bundle_path.is_absolute():
            bundle_path = base_dir / bundle_path
        config = entry.get("config", {})
        if not isinstance(config, dict):
            raise ValueError(
                f"Policy bundle for '{server}': 'config' must be an object of the "
                "facts the fetch plan's config entries read"
            )
        engine = entry.get("engine")
        if engine is not None and engine not in _POLICY_BUNDLE_ENGINES:
            raise ValueError(
                f"Policy bundle for '{server}': 'engine' must be one of "
                f"{list(_POLICY_BUNDLE_ENGINES)}, got {engine!r}"
            )
        single_use = entry.get("single_use", [])
        if not isinstance(single_use, list) or not all(
            isinstance(f, str) and f for f in single_use
        ):
            raise ValueError(
                f"Policy bundle for '{server}': 'single_use' must be a list of "
                "credential field names"
            )
        bundles[server] = PolicyBundleConfig(
            server=server,
            path=bundle_path,
            config=dict(config),
            engine=engine,
            single_use=list(single_use),
        )
    return bundles


def _resolve_tokens_file(path: Path, dotenv: dict[str, str]) -> Optional[Path]:
    tokens_env = os.environ.get("EXTENSIBLE_MCP_TOKENS_FILE") or dotenv.get(
        "EXTENSIBLE_MCP_TOKENS_FILE"
    )
    if tokens_env:
        tokens_path = _resolve_relative(tokens_env, path.parent)
        if not tokens_path.exists():
            raise FileNotFoundError(
                "Tokens file specified via EXTENSIBLE_MCP_TOKENS_FILE not found: "
                f"{tokens_path}"
            )
        return tokens_path
    tokens_path = path.parent / "tokens"
    return tokens_path if tokens_path.exists() else None


def load_config(path: Path) -> Config:
    with open(path) as f:
        raw: dict[str, Any] = json.load(f)

    dotenv = _load_dotenv(path.parent)
    credentials = _load_credentials(raw, path.parent)
    tokens_file = _resolve_tokens_file(path, dotenv)
    # Which names the tokens file holds an entry for, so that a
    # server configured both ways is refused rather than settled by a silent
    # precedence rule.
    tokens_entries = read_tokens_file(tokens_file) if tokens_file else {}

    servers: list[ServerConfig] = []
    for name, server_def in raw.get("mcpServers", {}).items():
        if not isinstance(server_def, dict):
            raise ValueError(f"Server '{name}' must be an object")
        if "command" not in server_def and "url" not in server_def:
            raise ValueError(f"Server '{name}' must have a 'command' or 'url' field")
        credential = server_def.get("credential")
        if credential is not None and credential not in credentials:
            raise ValueError(
                f"Server '{name}' names credential '{credential}', which is not "
                f"defined in 'credentials' (defined: {sorted(credentials) or 'none'})"
            )
        if credential is not None and name in tokens_entries:
            raise ValueError(
                f"Server '{name}' names credential '{credential}' and also has an "
                f"entry in the tokens file {tokens_file}. Which credential to "
                "present is ambiguous, and guessing would pick one silently: "
                f"remove the '{name}' line from the tokens file, or remove the "
                "'credential' field."
            )
        servers.append(
            ServerConfig(
                name=name,
                command=server_def.get("command"),
                args=server_def.get("args", []),
                env=_resolve_env_values(server_def.get("env"), dotenv),
                url=server_def.get("url"),
                credential=credential,
                scope=server_def.get("scope"),
                audience=server_def.get("audience"),
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

    policy_bundles = _load_policy_bundles(
        filters_raw.get("policy_bundles", {}),
        base_dir=path.parent,
        server_names={s.name for s in servers},
    )

    filters = FiltersConfig(
        similarity_threshold=filters_raw.get("similarity_threshold", 0.3),
        access_control=access_control,
        rego_policy=rego_policy,
        load_control=load_control,
        policy_bundles=policy_bundles,
    )

    if not servers:
        raise ValueError("Config must define at least one server in 'mcpServers'")

    return Config(
        servers=servers,
        filters=filters,
        tokens_file=tokens_file,
        credentials=credentials,
    )

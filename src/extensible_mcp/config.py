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
    GRANT_TOKEN_EXCHANGE,
    SUPPORTED_GRANTS,
)
from .native import (
    EXEC_TOOL,
    HTTP_REQUEST_TOOL,
    SHIPPED_SCHEMAS,
    HostRule,
    HttpRequestConfig,
    NativeTool,
    PlatformConfig,
    normalize_origin,
)
from .types import PLATFORM_SERVER, CredentialConfig, ServerConfig


@dataclass
class RoleScope:
    """What one role may see: the downstream servers (or ``"*"`` for every
    server not globally denied) and whether it may load a server at
    runtime."""

    allow_servers: list[str] | str = field(default_factory=list)
    may_load: bool = False


@dataclass
class AccessControlConfig:
    deny: list[str] = field(default_factory=list)
    deny_patterns: list[str] = field(default_factory=list)
    allow_servers: list[str] = field(default_factory=list)
    # Per-role scoping, keyed on the principal's roles. ``None`` means the
    # deployment-wide rules alone -- the single-tenant shape. Present, a
    # principal whose roles match no entry sees nothing.
    by_role: Optional[dict[str, RoleScope]] = None


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
class AuthConfig:
    """The ``auth`` block: inbound bearer verification, resource-server mode.

    The token presented to the proxy was issued by ``issuer`` to the MCP
    client, with the proxy as ``audience``; it is verified against the
    issuer's JWKS or one public key. That is all the block can express. The
    proxy fronting an identity provider as an authorization server is an
    embedder's choice, because it carries a client secret.
    """

    issuer: str
    audience: str
    jwks_uri: Optional[str] = None
    public_key_file: Optional[Path] = None
    algorithm: str = "RS256"


@dataclass
class PrincipalConfig:
    """The ``principal`` block: which claim holds the roles, by dotted path,
    and an optional total map from the issuer's values to the deployment's
    role names. No map means the values are our names already."""

    roles_claim: str = "roles"
    role_map: Optional[dict[str, str]] = None


#: The two ways the proxy answers ``tools/list``. ``dynamic`` is the three
#: meta-tools, and the model discovers the catalogue through ``search_tools``.
#: ``static`` is the governed catalogue itself, one entry per tool under its
#: qualified name, for a platform that loads a server's tools once and
#: dispatches them itself; every listed name still dispatches through the
#: same call path and the same filters.
EXPOSURES = ("dynamic", "static")


@dataclass
class Config:
    servers: list[ServerConfig] = field(default_factory=list)
    filters: FiltersConfig = field(default_factory=FiltersConfig)
    tokens_file: Optional[Path] = None
    credentials: dict[str, CredentialConfig] = field(default_factory=dict)
    auth: Optional[AuthConfig] = None
    principal: PrincipalConfig = field(default_factory=PrincipalConfig)
    exposure: str = "dynamic"
    # The ``platform`` pseudo-server: the native tools the endpoints may be
    # asked about, and whether the proxy runs ``http_request`` itself. ``None``
    # is a proxy with no native tools, which is every deployment before 0.4.1.
    platform: Optional[PlatformConfig] = None

    def __post_init__(self) -> None:
        if self.exposure not in EXPOSURES:
            raise ValueError(
                f"'exposure' must be one of {list(EXPOSURES)}, not {self.exposure!r}"
            )


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
    # The proxy authenticates to the exchange with exactly one of the two.
    GRANT_TOKEN_EXCHANGE: frozenset({"private_key_file", "client_secret_env"}),
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
        elif grant == GRANT_CLIENT_CREDENTIALS:
            client_secret_env = entry.get("client_secret_env")
            if not client_secret_env:
                raise ValueError(
                    f"Credential '{name}' uses the client_credentials grant, so it "
                    "must have a 'client_secret_env' field naming the environment "
                    "variable that holds the secret"
                )
        else:
            key_file = entry.get("private_key_file")
            client_secret_env = entry.get("client_secret_env")
            if bool(key_file) == bool(client_secret_env):
                raise ValueError(
                    f"Credential '{name}' uses the token_exchange grant, so it "
                    "must have exactly one of 'private_key_file' (the proxy signs "
                    "an assertion) or 'client_secret_env' (the proxy sends a "
                    "secret) for the proxy's own client authentication at the "
                    "exchange"
                )
            if key_file:
                private_key_file = _resolve_relative(key_file, config_dir)
                client_secret_env = None

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
    ``bundle_router`` governs; a name that is not in ``mcpServers`` (or the
    ``platform`` pseudo-server, when the config declares native tools) is a
    typo that would otherwise leave a gate declared and never attached, which
    is the quiet failure this loader exists to refuse. Unknown keys are refused
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


_PLATFORM_KEYS = frozenset({"tools", "http_request"})
_NATIVE_TOOL_KEYS = frozenset({"description", "input_schema"})
_HTTP_REQUEST_KEYS = frozenset({"hosts", "timeout", "max_response"})
_HOST_KEYS = frozenset({"methods", "paths", "headers", "credential"})


def _load_native_tools(raw: Any) -> dict[str, NativeTool]:
    if not isinstance(raw, dict):
        raise ValueError("'platform.tools' must be an object mapping a tool name to its declaration")
    tools: dict[str, NativeTool] = {}
    for name, entry in raw.items():
        if not isinstance(name, str) or not name:
            raise ValueError("'platform.tools' has an empty tool name")
        if "__" in name:
            raise ValueError(
                f"Platform tool name {name!r} must not contain '__'; it is listed as "
                f"'{PLATFORM_SERVER}__{name}' and the separator is reserved"
            )
        if not isinstance(entry, dict):
            raise ValueError(f"Platform tool '{name}' must be an object")
        unknown = sorted(set(entry) - _NATIVE_TOOL_KEYS)
        if unknown:
            raise ValueError(
                f"Platform tool '{name}' has unexpected field(s) {unknown}; "
                f"allowed: {sorted(_NATIVE_TOOL_KEYS)}"
            )
        shipped = SHIPPED_SCHEMAS.get(name)
        description = entry.get("description", shipped[0] if shipped else None)
        schema = entry.get("input_schema", shipped[1] if shipped else None)
        if not isinstance(description, str) or not description:
            raise ValueError(
                f"Platform tool '{name}' needs a 'description': only "
                f"{sorted(SHIPPED_SCHEMAS)} ship with one"
            )
        if not isinstance(schema, dict):
            raise ValueError(
                f"Platform tool '{name}' needs an 'input_schema' object: a policy can "
                "judge a native tool only as far as its declared arguments say what "
                f"it does, and only {sorted(SHIPPED_SCHEMAS)} ship with a schema"
            )
        tools[name] = NativeTool(name=name, description=description, input_schema=schema)
    return tools


def _load_http_request(raw: Any, credentials: dict[str, CredentialConfig]) -> HttpRequestConfig:
    if not isinstance(raw, dict):
        raise ValueError("'platform.http_request' must be an object")
    unknown = sorted(set(raw) - _HTTP_REQUEST_KEYS)
    if unknown:
        raise ValueError(
            f"'platform.http_request' has unexpected field(s) {unknown}; "
            f"allowed: {sorted(_HTTP_REQUEST_KEYS)}"
        )
    hosts_raw = raw.get("hosts")
    if not isinstance(hosts_raw, dict) or not hosts_raw:
        raise ValueError(
            "'platform.http_request.hosts' must be a non-empty object mapping an "
            "origin (scheme://host[:port]) to what the proxy may send it; with no "
            "hosts the proxy would run nothing, so declare none instead"
        )
    hosts: dict[str, HostRule] = {}
    for origin_raw, entry in hosts_raw.items():
        try:
            origin = normalize_origin(origin_raw)
        except ValueError as e:
            raise ValueError(f"'platform.http_request.hosts': {e}")
        if origin in hosts:
            raise ValueError(f"'platform.http_request.hosts' names {origin} twice")
        if not isinstance(entry, dict):
            raise ValueError(f"Host entry for {origin} must be an object")
        unknown = sorted(set(entry) - _HOST_KEYS)
        if unknown:
            raise ValueError(
                f"Host entry for {origin} has unexpected field(s) {unknown}; "
                f"allowed: {sorted(_HOST_KEYS)}"
            )
        methods = entry.get("methods", ["GET"])
        if not isinstance(methods, list) or not methods or not all(
            isinstance(m, str) and m for m in methods
        ):
            raise ValueError(f"Host entry for {origin}: 'methods' must be a non-empty list of methods")
        paths = entry.get("paths", [])
        if not isinstance(paths, list) or not all(isinstance(p, str) and p.startswith("/") for p in paths):
            raise ValueError(f"Host entry for {origin}: 'paths' must be a list of path prefixes starting with '/'")
        headers = entry.get("headers", [])
        if not isinstance(headers, list) or not all(isinstance(h, str) and h for h in headers):
            raise ValueError(f"Host entry for {origin}: 'headers' must be a list of header names")
        if any(h.lower() == "authorization" for h in headers):
            raise ValueError(
                f"Host entry for {origin}: 'headers' may not list Authorization; the "
                "proxy sets it from 'credential'"
            )
        credential = entry.get("credential")
        if credential is not None and credential not in credentials:
            raise ValueError(
                f"Host entry for {origin} names credential '{credential}', which is not "
                f"defined in 'credentials' (defined: {sorted(credentials) or 'none'})"
            )
        if credential is not None and credentials[credential].grant == GRANT_TOKEN_EXCHANGE:
            # The rider presents the credential the proxy holds for the host,
            # the proxy's own; a delegated one would need the caller's token
            # on the rider's path, which this release does not carry there.
            raise ValueError(
                f"Host entry for {origin} names credential '{credential}', whose "
                "grant is token_exchange. platform.http_request presents the "
                "proxy's own credential for a host; a per-caller one is not "
                "supported there. Use a client_credentials or private_key_jwt "
                "credential for the host."
            )
        hosts[origin] = HostRule(
            origin=origin,
            methods=frozenset(m.upper() for m in methods),
            paths=tuple(paths),
            headers=frozenset(headers),
            credential=credential,
        )
    timeout = raw.get("timeout", 30)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ValueError("'platform.http_request.timeout' must be a positive number of seconds")
    max_response = raw.get("max_response", 1024 * 1024)
    if isinstance(max_response, bool) or not isinstance(max_response, int) or max_response <= 0:
        raise ValueError("'platform.http_request.max_response' must be a positive number of bytes")
    return HttpRequestConfig(hosts=hosts, timeout=float(timeout), max_response=max_response)


def _load_platform(raw: dict[str, Any], credentials: dict[str, CredentialConfig]) -> Optional[PlatformConfig]:
    """Parse the ``platform`` block, refusing anything ambiguous.

    A declared native tool is one the endpoints may be asked about, so its
    arguments have to be declared: a policy judges a native tool only as far
    as its schema says what the tool does. ``exec`` and ``http_request`` ship
    with theirs. The ``http_request`` block additionally makes that one tool
    executable by the proxy, and declares the tool if the block did not.
    """
    if "platform" not in raw:
        return None
    block = raw["platform"]
    if not isinstance(block, dict):
        raise ValueError("'platform' must be an object with 'tools' and/or 'http_request'")
    unknown = sorted(set(block) - _PLATFORM_KEYS)
    if unknown:
        raise ValueError(
            f"'platform' has unexpected field(s) {unknown}; allowed: {sorted(_PLATFORM_KEYS)}"
        )
    tools = _load_native_tools(block.get("tools", {}))
    http_request: HttpRequestConfig | None = None
    if "http_request" in block:
        http_request = _load_http_request(block["http_request"], credentials)
        if HTTP_REQUEST_TOOL not in tools:
            description, schema = SHIPPED_SCHEMAS[HTTP_REQUEST_TOOL]
            tools[HTTP_REQUEST_TOOL] = NativeTool(HTTP_REQUEST_TOOL, description, schema)
    if not tools:
        raise ValueError(
            "'platform' declares no tools: list them under 'platform.tools' "
            f"({EXEC_TOOL!r} and {HTTP_REQUEST_TOOL!r} take an empty object), or "
            "remove the block"
        )
    return PlatformConfig(tools=tools, http_request=http_request)


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


_AUTH_KEYS = ("issuer", "audience", "jwks_uri", "public_key_file", "algorithm")
_PRINCIPAL_KEYS = ("roles_claim", "role_map")


_ROLE_SCOPE_KEYS = ("allow_servers", "may_load")


def _load_by_role(raw: Any) -> Optional[dict[str, RoleScope]]:
    """Parse ``access_control.by_role``: role -> what that role may see."""
    if raw is None:
        return None
    if not isinstance(raw, dict) or not raw:
        raise ValueError(
            "'access_control.by_role' must be a non-empty object mapping a role "
            "name to {allow_servers, may_load}; omit it for no per-role scoping"
        )
    out: dict[str, RoleScope] = {}
    for role, entry in raw.items():
        if not isinstance(entry, dict):
            raise ValueError(f"'access_control.by_role.{role}' must be an object")
        unknown = sorted(set(entry) - set(_ROLE_SCOPE_KEYS))
        if unknown:
            raise ValueError(
                f"'access_control.by_role.{role}' has unexpected field(s) {unknown}; "
                f"allowed: {list(_ROLE_SCOPE_KEYS)}"
            )
        servers = entry.get("allow_servers")
        if servers != "*" and not (
            isinstance(servers, list) and all(isinstance(x, str) and x for x in servers)
        ):
            raise ValueError(
                f"'access_control.by_role.{role}.allow_servers' must be a list of server "
                "names, or \"*\" for every server not globally denied"
            )
        may_load = entry.get("may_load", False)
        if not isinstance(may_load, bool):
            raise ValueError(f"'access_control.by_role.{role}.may_load' must be a boolean")
        out[role] = RoleScope(allow_servers=servers if servers == "*" else list(servers), may_load=may_load)
    return out


def _load_auth(raw: dict[str, Any], config_dir: Path) -> Optional[AuthConfig]:
    """Parse the ``auth`` block, refusing anything ambiguous."""
    if "auth" not in raw:
        return None
    block = raw["auth"]
    if not isinstance(block, dict):
        raise ValueError("'auth' must be an object")
    unknown = sorted(set(block) - set(_AUTH_KEYS))
    if unknown:
        if "client_secret" in unknown or "client_secret_env" in unknown:
            raise ValueError(
                "'auth' carries a client secret. The config form verifies tokens "
                "an authorization server issued to the client, with the proxy as "
                "audience; it is never an OAuth client itself. A proxy that fronts "
                "an identity provider is wired from an entry point: "
                "create_server(auth=OIDCProxy(...))."
            )
        raise ValueError(f"'auth' has unexpected field(s) {unknown}; allowed: {list(_AUTH_KEYS)}")
    for key in ("issuer", "audience"):
        if not isinstance(block.get(key), str) or not block[key]:
            raise ValueError(f"'auth' must have a non-empty '{key}'")
    jwks_uri = block.get("jwks_uri")
    key_file = block.get("public_key_file")
    if (jwks_uri is None) == (key_file is None):
        raise ValueError(
            "'auth' must name exactly one of 'jwks_uri' (the issuer's key set) or "
            "'public_key_file' (one PEM public key)"
        )
    if jwks_uri is not None and (not isinstance(jwks_uri, str) or not jwks_uri):
        raise ValueError("'auth.jwks_uri' must be a URL")
    public_key_file: Optional[Path] = None
    if key_file is not None:
        if not isinstance(key_file, str) or not key_file:
            raise ValueError("'auth.public_key_file' must be a path")
        public_key_file = _resolve_relative(key_file, config_dir)
        if not public_key_file.is_file():
            raise ValueError(f"'auth.public_key_file' {str(public_key_file)!r} is not a file")
    algorithm = block.get("algorithm", "RS256")
    if not isinstance(algorithm, str) or not algorithm:
        raise ValueError("'auth.algorithm' must be a string")
    return AuthConfig(
        issuer=block["issuer"],
        audience=block["audience"],
        jwks_uri=jwks_uri,
        public_key_file=public_key_file,
        algorithm=algorithm,
    )


def _load_principal(raw: dict[str, Any]) -> PrincipalConfig:
    """Parse the ``principal`` block. Absent, roles are read from ``roles``
    verbatim."""
    if "principal" not in raw:
        return PrincipalConfig()
    block = raw["principal"]
    if not isinstance(block, dict):
        raise ValueError("'principal' must be an object")
    unknown = sorted(set(block) - set(_PRINCIPAL_KEYS))
    if unknown:
        raise ValueError(
            f"'principal' has unexpected field(s) {unknown}; allowed: {list(_PRINCIPAL_KEYS)}"
        )
    roles_claim = block.get("roles_claim", "roles")
    if not isinstance(roles_claim, str) or not roles_claim:
        raise ValueError("'principal.roles_claim' must be a dotted claim path")
    role_map = block.get("role_map")
    if role_map is not None:
        if not isinstance(role_map, dict) or not all(
            isinstance(k, str) and isinstance(v, str) and v for k, v in role_map.items()
        ):
            raise ValueError(
                "'principal.role_map' must map the issuer's role values (strings) to "
                "this deployment's role names (strings)"
            )
        role_map = dict(role_map)
    return PrincipalConfig(roles_claim=roles_claim, role_map=role_map)


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
        by_role=_load_by_role(ac_raw.get("by_role")),
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

    platform = _load_platform(raw, credentials)
    # ``platform`` is the one bundle key that is not in ``mcpServers``: it is
    # the server the proxy itself provides, and a bundle on it governs the
    # declared native tools. Accepted only when the block declares some,
    # since a bundle on no tools is the gate-declared-never-attached failure
    # the loader refuses everywhere else.
    bundle_targets = {s.name for s in servers}
    if platform is not None:
        bundle_targets.add(PLATFORM_SERVER)
    policy_bundles = _load_policy_bundles(
        filters_raw.get("policy_bundles", {}),
        base_dir=path.parent,
        server_names=bundle_targets,
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

    exposure = raw.get("exposure", "dynamic")
    if not isinstance(exposure, str) or exposure not in EXPOSURES:
        raise ValueError(f"'exposure' must be one of {list(EXPOSURES)}, not {exposure!r}")

    return Config(
        servers=servers,
        filters=filters,
        tokens_file=tokens_file,
        credentials=credentials,
        auth=_load_auth(raw, path.parent),
        principal=_load_principal(raw),
        exposure=exposure,
        platform=platform,
    )

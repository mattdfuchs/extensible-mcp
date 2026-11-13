# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


#: The proxy's own tools. A local tool may not take one of these names: under
#: static exposure the catalogue is listed in their place, and a local tool
#: so named would be listed, and called, as if it were the meta-tool.
META_TOOL_NAMES: frozenset[str] = frozenset({"search_tools", "call_tool", "load_mcp_server"})

#: The pseudo-server the proxy itself provides. A platform's native steps --
#: a shell command, an HTTP request, a function tool -- are tools of this
#: server (``platform__exec``, ``platform__http_request``), so everything the
#: proxy decides with, all of it keyed on the server name, applies to them
#: with no second code path. No downstream server may take the name: one
#: that did would be governed as the proxy's own tools and dispatched as a
#: stranger's.
PLATFORM_SERVER = "platform"


def _reject_separator(name: str, what: str) -> None:
    """``__`` splits a qualified tool name back into server and tool, so a
    name containing it re-parses as a *different* server — which would let
    the call escape per-server policy routing and call-side access control
    while still being dispatched. Rejected at construction, everywhere."""
    if "__" in name:
        raise ValueError(
            f"{what} name {name!r} must not contain '__' — that separator is "
            "reserved for qualified tool names ({server}__{tool})."
        )


@dataclass(frozen=True)
class CredentialConfig:
    """A named OAuth client identity the proxy authenticates itself with.

    Grant, token endpoint and client identity belong to the credential; the
    ``scope`` and ``audience`` of a token belong to the *server* it is
    presented to, because one OAuth client legitimately serves many
    resources. See ``credentials.py`` for the grants and what each keeps at
    rest.

    There is deliberately no field for an inline client secret: ``config.json``
    is a file people commit and share, so the secret is named
    (``client_secret_env``) rather than carried.
    """

    name: str
    grant: str
    token_endpoint: str
    client_id: str
    private_key_file: Path | None = None
    client_secret_env: str | None = None


@dataclass
class ServerConfig:
    """Configuration for a downstream MCP server.

    Either ``command`` (stdio) or ``url`` (Streamable HTTP) must be set.

    ``credential`` names an entry in the config's ``credentials`` block; the
    token acquired with it is scoped by ``scope`` and bound to ``audience``.
    """

    name: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None
    url: str | None = None
    credential: str | None = None
    scope: str | None = None
    audience: str | None = None

    def __post_init__(self) -> None:
        if not self.command and not self.url:
            raise ValueError(f"Server '{self.name}' must have either 'command' or 'url'")
        if self.command and self.url:
            raise ValueError(f"Server '{self.name}' must have 'command' or 'url', not both")
        if self.command and (self.credential or self.scope or self.audience):
            # A credential is presented as an Authorization header over HTTP.
            # Accepting one on a stdio server would look configured and do
            # nothing, which is worse than refusing it.
            raise ValueError(
                f"Server '{self.name}' is a stdio server, so it cannot carry "
                "'credential', 'scope' or 'audience' -- those apply to a 'url' server"
            )
        if (self.scope or self.audience) and not self.credential:
            raise ValueError(
                f"Server '{self.name}' sets 'scope' or 'audience' but names no "
                "'credential', so neither would be used by anything"
            )
        _reject_separator(self.name, "Server")
        if self.name == PLATFORM_SERVER:
            raise ValueError(
                f"Server name {PLATFORM_SERVER!r} is reserved: it is the "
                "pseudo-server for the platform's own tools (platform__exec, "
                "platform__http_request), declared under 'platform', not 'mcpServers'."
            )


@dataclass
class ToolRecord:
    """A tool definition indexed from a downstream server."""

    name: str
    qualified_name: str  # {server}__{tool}
    description: str
    input_schema: dict[str, Any]
    server_name: str
    embedding_text: str = ""

    def __post_init__(self) -> None:
        if not self.embedding_text:
            self.embedding_text = self._build_embedding_text()

    def _build_embedding_text(self) -> str:
        parts = [f"{self.qualified_name}: {self.description}"]
        properties = self.input_schema.get("properties", {})
        required = set(self.input_schema.get("required", []))
        if properties:
            param_strs = []
            for param_name, param_info in properties.items():
                param_type = param_info.get("type", "any")
                req = "required" if param_name in required else "optional"
                param_strs.append(f"{param_name} ({param_type}, {req})")
            parts.append("Parameters: " + ", ".join(param_strs))
        return ". ".join(parts)


@dataclass
class LocalTool:
    """An in-process tool the embedder registers alongside downstream
    servers. Dispatched through the same call_tool/CallFilterPipeline path
    as a downstream tool — discovered via search_tools, invoked via
    call_tool, gated by every CallFilter exactly like a downstream one.

    ``name`` must not contain "__" — that separator is reserved for the
    {server}__{tool} downstream namespace — which is what gives a local
    tool ``server_name=""`` wherever call/response records key on it.
    """

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], Awaitable[Any]]

    def __post_init__(self) -> None:
        _reject_separator(self.name, "Local tool")
        if self.name in META_TOOL_NAMES:
            raise ValueError(
                f"Local tool name {self.name!r} is reserved: it is one of the "
                f"proxy's own tools ({', '.join(sorted(META_TOOL_NAMES))})."
            )


@dataclass
class SearchResult:
    """A tool matched by vector search, with its similarity score."""

    tool: ToolRecord
    score: float


@dataclass(frozen=True)
class Principal:
    """Who a session acts for, as the verified inbound token asserts it.

    Built from a token's claims by :mod:`extensible_mcp.principal` and never
    from anything the model supplies. ``sub`` and ``iss`` identify the user
    at the issuer; ``roles`` are the deployment's own role names, after the
    configured mapping; ``client_id`` is the agent the token was issued to,
    so "user U via agent A" is one value and not two. ``auth_time``, ``amr``
    and ``acr`` are what the issuer said about how the user authenticated,
    ``None`` when it said nothing.

    **Never the raw token.** Requests are rebuilt and logged, and a principal
    is a fact about identity, not a credential that could be replayed.
    """

    sub: str
    iss: str
    roles: frozenset[str] = frozenset()
    client_id: str | None = None
    auth_time: int | None = None
    amr: tuple[str, ...] | None = None
    acr: str | None = None


@dataclass
class CallRequest:
    """Input to the call filter pipeline.

    ``session_id`` is the framework's identifier for the connection the call
    arrived on. On the protocol's 2026-07-28 revision every request is its own
    connection and the value is fresh each time, so it identifies nothing
    across calls and no filter keys state on it; it is carried for logging.
    (Until that revision it was the MCP session, and ``DiscoveredToolsFilter``
    scoped on it; that filter now scopes on ``principal``.)

    It is deliberately *not* an identity claim. It says which connection this
    came from, not who the connection acts for. That is ``principal``: the
    :class:`Principal` the verified inbound token established for the session,
    or ``None`` when the deployment has no inbound auth (stdio, where the
    process serves one person, or an HTTP deployment that opted out with
    ``require_principal=False``). A filter that keys on identity treats
    ``None`` as "no principal", never as "anyone".

    ``verdict_only`` says the caller is asking whether this call would be
    allowed and is not making it through this request: the ``POST /decide``
    endpoint, where a platform asks about a step it will run itself. Every
    filter sees the flag, and the contract is that **a filter whose effect
    goes beyond its answer has none when it is set**. The replay guard
    honours it by reserving and then releasing the evidence whichever way
    the policy answered, so a spent approval is still refused and an unspent
    one stays spendable by the real call that follows. A custom filter that
    logs, counts or spends must read it the same way.
    """

    tool_name: str
    arguments: dict[str, Any]
    server_name: str
    session_id: str | None = None
    principal: Principal | None = None
    verdict_only: bool = False


@dataclass
class CallFilterResult:
    """Output from a call filter. If allowed=False, pipeline short-circuits."""

    allowed: bool
    reason: str = ""
    tool_name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class ServerLoadRequest:
    """Input to the server load filter pipeline. ``principal`` as on
    :class:`CallRequest`."""

    server_name: str
    url: str
    principal: Principal | None = None


@dataclass
class ServerLoadResult:
    """Output from a server load filter. If allowed=False, pipeline short-circuits."""

    allowed: bool
    reason: str = ""


@dataclass
class CallResponse:
    """Input to the response filter pipeline.

    ``content`` is the list of MCP content blocks returned by the downstream
    server (typically ``mcp.types.TextContent`` and friends). Filters may
    inspect, modify, or replace these blocks.

    ``structured_content`` is the downstream's ``structuredContent``: the
    result as a JSON object, when the tool declares an ``outputSchema`` or
    the server produces one anyway. For a local tool it is the handler's
    return value when that is an object. A response filter that wants to
    read a result reads this rather than parsing text out of ``content``.
    It is forwarded to filters, not rewritten by them: ``content`` and
    ``is_error`` are the fields a filter may replace.
    """

    tool_name: str
    arguments: dict[str, Any]
    server_name: str
    content: list[Any] = field(default_factory=list)
    is_error: bool = False
    structured_content: dict[str, Any] | None = None
    principal: Principal | None = None


@dataclass
class ResponseFilterResult:
    """Output from a response filter.

    If ``allowed=False``, the pipeline short-circuits and the LLM sees an
    error string built from ``reason`` instead of the content. Otherwise
    ``content`` and ``is_error`` are passed to the next filter (or to the
    final response formatting).
    """

    allowed: bool
    reason: str = ""
    content: list[Any] = field(default_factory=list)
    is_error: bool = False

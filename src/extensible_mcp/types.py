# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


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


@dataclass
class SearchResult:
    """A tool matched by vector search, with its similarity score."""

    tool: ToolRecord
    score: float


@dataclass
class CallRequest:
    """Input to the call filter pipeline.

    ``session_id`` identifies the MCP session the call arrived on, when the
    transport has one — ``None`` on stdio, where a process serves exactly one
    client and the distinction is empty. It exists so a filter can scope state
    to the conversation that created it rather than to the process; see
    ``DiscoveredToolsFilter``.

    It is deliberately *not* an identity claim. It says which connection this
    came from, not who the connection acts for. Nothing about the principal
    behind a session is established anywhere in the proxy today.
    """

    tool_name: str
    arguments: dict[str, Any]
    server_name: str
    session_id: str | None = None


@dataclass
class CallFilterResult:
    """Output from a call filter. If allowed=False, pipeline short-circuits."""

    allowed: bool
    reason: str = ""
    tool_name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class ServerLoadRequest:
    """Input to the server load filter pipeline."""

    server_name: str
    url: str


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
    """

    tool_name: str
    arguments: dict[str, Any]
    server_name: str
    content: list[Any] = field(default_factory=list)
    is_error: bool = False


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

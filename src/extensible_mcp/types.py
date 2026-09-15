# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ServerConfig:
    """Configuration for a downstream MCP server.

    Either ``command`` (stdio) or ``url`` (Streamable HTTP) must be set.
    """

    name: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None
    url: str | None = None

    def __post_init__(self) -> None:
        if not self.command and not self.url:
            raise ValueError(f"Server '{self.name}' must have either 'command' or 'url'")
        if self.command and self.url:
            raise ValueError(f"Server '{self.name}' must have 'command' or 'url', not both")


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


@dataclass
class SearchResult:
    """A tool matched by vector search, with its similarity score."""

    tool: ToolRecord
    score: float


@dataclass
class CallRequest:
    """Input to the call filter pipeline."""

    tool_name: str
    arguments: dict[str, Any]
    server_name: str


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

from __future__ import annotations

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

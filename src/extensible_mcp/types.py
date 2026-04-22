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
class ToolPolicy:
    """Policy for a tool pattern — used by both search-side injection and call-side validation."""

    tool_pattern: str
    required_arguments: dict[str, Any] = field(default_factory=dict)

    def matches(self, qualified_name: str) -> bool:
        import fnmatch

        return fnmatch.fnmatch(qualified_name, self.tool_pattern)

    def validate(self, arguments: dict[str, Any]) -> tuple[bool, str]:
        for key, expected in self.required_arguments.items():
            if key not in arguments:
                return False, f"Missing required argument '{key}' (expected value: {expected!r})"
            if arguments[key] != expected:
                return False, (
                    f"Argument '{key}' has value {arguments[key]!r}, "
                    f"expected {expected!r}"
                )
        return True, ""

    def describe_requirements(self) -> str:
        parts = []
        for key, value in self.required_arguments.items():
            parts.append(f"'{key}' must be {value!r}")
        return "SECURITY REQUIREMENTS: " + "; ".join(parts)


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

from __future__ import annotations

import fnmatch
import json
import re
from typing import Any, Protocol

from .types import (
    CallFilterResult,
    CallRequest,
    SearchResult,
    ServerLoadRequest,
    ServerLoadResult,
)


class ToolFilter(Protocol):
    def filter(self, results: list[SearchResult], query: str) -> list[SearchResult]:
        """Filter or reorder search results. Return the filtered list."""
        ...


class SimilarityThresholdFilter:
    def __init__(self, min_score: float = 0.3) -> None:
        self.min_score = min_score

    def filter(self, results: list[SearchResult], query: str) -> list[SearchResult]:
        return [r for r in results if r.score >= self.min_score]


class AccessControlFilter:
    def __init__(
        self,
        deny: list[str] | None = None,
        deny_patterns: list[str] | None = None,
        allow_servers: list[str] | None = None,
    ) -> None:
        self.deny: set[str] = set(deny or [])
        self.deny_patterns: list[str] = list(deny_patterns or [])
        self.allow_servers: set[str] = set(allow_servers) if allow_servers else set()

    def is_allowed(self, qualified_name: str, server_name: str) -> bool:
        if qualified_name in self.deny:
            return False
        for pattern in self.deny_patterns:
            if fnmatch.fnmatch(qualified_name, pattern):
                return False
        if self.allow_servers and server_name not in self.allow_servers:
            return False
        return True

    def filter(self, results: list[SearchResult], query: str) -> list[SearchResult]:
        return [
            r
            for r in results
            if self.is_allowed(r.tool.qualified_name, r.tool.server_name)
        ]

    async def check(self, request: CallRequest) -> CallFilterResult:
        if self.is_allowed(request.tool_name, request.server_name):
            return CallFilterResult(
                allowed=True,
                tool_name=request.tool_name,
                arguments=request.arguments,
            )
        return CallFilterResult(
            allowed=False,
            reason=f"Tool '{request.tool_name}' is blocked by access control policy.",
            tool_name=request.tool_name,
            arguments=request.arguments,
        )


class FilterPipeline:
    def __init__(self, filters: list[ToolFilter] | None = None) -> None:
        self.filters: list[ToolFilter] = list(filters or [])

    def add(self, f: ToolFilter) -> None:
        self.filters.append(f)

    def apply(self, results: list[SearchResult], query: str) -> list[SearchResult]:
        for f in self.filters:
            results = f.filter(results, query)
        return results


class CallFilter(Protocol):
    async def check(self, request: CallRequest) -> CallFilterResult:
        """Check whether a call should proceed. Return the result."""
        ...


class CallFilterPipeline:
    def __init__(self, filters: list[CallFilter] | None = None) -> None:
        self.filters: list[CallFilter] = list(filters or [])

    def add(self, f: CallFilter) -> None:
        self.filters.append(f)

    async def apply(self, request: CallRequest) -> CallFilterResult:
        tool_name = request.tool_name
        arguments = dict(request.arguments)
        for f in self.filters:
            result = await f.check(
                CallRequest(
                    tool_name=tool_name,
                    arguments=arguments,
                    server_name=request.server_name,
                )
            )
            if not result.allowed:
                return result
            tool_name = result.tool_name
            arguments = result.arguments
        return CallFilterResult(
            allowed=True, tool_name=tool_name, arguments=arguments
        )


class DiscoveredToolsFilter:
    """Call-side filter: only allows tools previously returned by search_tools."""

    def __init__(self) -> None:
        self._discovered: set[str] = set()

    def register(self, tool_names: list[str]) -> None:
        self._discovered.update(tool_names)

    async def check(self, request: CallRequest) -> CallFilterResult:
        if request.tool_name in self._discovered:
            return CallFilterResult(
                allowed=True,
                tool_name=request.tool_name,
                arguments=request.arguments,
            )
        return CallFilterResult(
            allowed=False,
            reason=f"Tool '{request.tool_name}' has not been discovered via search_tools. Search for tools first.",
            tool_name=request.tool_name,
            arguments=request.arguments,
        )


class RegoPolicyFilter:
    """Call-side filter: evaluates a Rego policy to allow or deny tool calls."""

    def __init__(self, policy_path: str) -> None:
        try:
            import regopy  # noqa: F401
        except ImportError:
            raise ImportError(
                "regopy is required for Rego policy support. "
                "Install it with: uv sync --group rego"
            )
        with open(policy_path) as f:
            self._policy_source = f.read()
        match = re.search(r"^package\s+(\S+)", self._policy_source, re.MULTILINE)
        if not match:
            raise ValueError(f"Rego policy at '{policy_path}' must declare a package")
        self._package = match.group(1)

    async def check(self, request: CallRequest) -> CallFilterResult:
        import regopy

        interpreter = regopy.Interpreter()
        interpreter.add_module("policy", self._policy_source)
        input_data: dict[str, Any] = {
            "tool_name": request.tool_name,
            "arguments": request.arguments,
            "server_name": request.server_name,
        }
        interpreter.set_input(input_data)

        output = interpreter.query(f"data.{self._package}.allow")
        output_str = str(output)

        if output_str != "undefined":
            parsed = json.loads(output_str)
            if parsed.get("expressions", [None])[0] is True:
                return CallFilterResult(
                    allowed=True,
                    tool_name=request.tool_name,
                    arguments=request.arguments,
                )

        # Denied — try to get a reason
        reason = f"Tool '{request.tool_name}' blocked by Rego policy."
        reason_output = interpreter.query(f"data.{self._package}.deny_reason")
        reason_str = str(reason_output)
        if reason_str != "undefined":
            parsed_reason = json.loads(reason_str)
            exprs = parsed_reason.get("expressions", [])
            if exprs and isinstance(exprs[0], str):
                reason = exprs[0]

        return CallFilterResult(
            allowed=False,
            reason=reason,
            tool_name=request.tool_name,
            arguments=request.arguments,
        )


class ServerLoadFilter(Protocol):
    async def check(self, request: ServerLoadRequest) -> ServerLoadResult:
        """Check whether a server load request should proceed."""
        ...


class ServerLoadFilterPipeline:
    def __init__(self, filters: list[ServerLoadFilter] | None = None) -> None:
        self.filters: list[ServerLoadFilter] = list(filters or [])

    def add(self, f: ServerLoadFilter) -> None:
        self.filters.append(f)

    async def apply(self, request: ServerLoadRequest) -> ServerLoadResult:
        for f in self.filters:
            result = await f.check(request)
            if not result.allowed:
                return result
        return ServerLoadResult(allowed=True)


class ServerLoadAccessControlFilter:
    """Config-driven allow/deny for server names and URLs."""

    def __init__(
        self,
        deny_names: list[str] | None = None,
        deny_name_patterns: list[str] | None = None,
        deny_url_patterns: list[str] | None = None,
        allow_url_patterns: list[str] | None = None,
    ) -> None:
        self.deny_names: set[str] = set(deny_names or [])
        self.deny_name_patterns: list[str] = list(deny_name_patterns or [])
        self.deny_url_patterns: list[str] = list(deny_url_patterns or [])
        self.allow_url_patterns: list[str] = list(allow_url_patterns or [])

    async def check(self, request: ServerLoadRequest) -> ServerLoadResult:
        if request.server_name in self.deny_names:
            return ServerLoadResult(
                allowed=False,
                reason=f"Server name '{request.server_name}' is blocked by load control policy.",
            )
        for pattern in self.deny_name_patterns:
            if fnmatch.fnmatch(request.server_name, pattern):
                return ServerLoadResult(
                    allowed=False,
                    reason=f"Server name '{request.server_name}' matches blocked pattern '{pattern}'.",
                )
        for pattern in self.deny_url_patterns:
            if fnmatch.fnmatch(request.url, pattern):
                return ServerLoadResult(
                    allowed=False,
                    reason=f"URL '{request.url}' matches blocked pattern '{pattern}'.",
                )
        if self.allow_url_patterns:
            if not any(fnmatch.fnmatch(request.url, p) for p in self.allow_url_patterns):
                return ServerLoadResult(
                    allowed=False,
                    reason=f"URL '{request.url}' does not match any allowed URL pattern.",
                )
        return ServerLoadResult(allowed=True)

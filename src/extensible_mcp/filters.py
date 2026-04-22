from __future__ import annotations

import fnmatch
from typing import Protocol

from .types import (
    CallFilterResult,
    CallRequest,
    SearchResult,
    ServerLoadRequest,
    ServerLoadResult,
    ToolPolicy,
    ToolRecord,
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


class RequirementInjectionFilter:
    """Search-side filter: appends security requirement text to matching tool descriptions."""

    def __init__(self, policies: list[ToolPolicy]) -> None:
        self.policies = policies

    def filter(self, results: list[SearchResult], query: str) -> list[SearchResult]:
        out: list[SearchResult] = []
        for r in results:
            matching = [p for p in self.policies if p.matches(r.tool.qualified_name)]
            if matching:
                extra = "\n\n".join(p.describe_requirements() for p in matching)
                modified_tool = ToolRecord(
                    name=r.tool.name,
                    qualified_name=r.tool.qualified_name,
                    description=r.tool.description + "\n\n" + extra,
                    input_schema=r.tool.input_schema,
                    server_name=r.tool.server_name,
                    embedding_text=r.tool.embedding_text,
                )
                out.append(SearchResult(tool=modified_tool, score=r.score))
            else:
                out.append(r)
        return out


class RequirementValidationFilter:
    """Call-side filter: validates that arguments satisfy policy requirements."""

    def __init__(self, policies: list[ToolPolicy]) -> None:
        self.policies = policies

    async def check(self, request: CallRequest) -> CallFilterResult:
        policy_keys: set[str] = set()
        for policy in self.policies:
            if policy.matches(request.tool_name):
                valid, reason = policy.validate(request.arguments)
                if not valid:
                    return CallFilterResult(
                        allowed=False,
                        reason=reason,
                        tool_name=request.tool_name,
                        arguments=request.arguments,
                    )
                policy_keys.update(policy.required_arguments.keys())
        # Strip policy-enforced arguments before forwarding to downstream server
        forwarded = {k: v for k, v in request.arguments.items() if k not in policy_keys}
        return CallFilterResult(
            allowed=True,
            tool_name=request.tool_name,
            arguments=forwarded,
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

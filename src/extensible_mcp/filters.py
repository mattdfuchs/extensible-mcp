from __future__ import annotations

import fnmatch
from typing import Protocol

from .types import SearchResult


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


class FilterPipeline:
    def __init__(self, filters: list[ToolFilter] | None = None) -> None:
        self.filters: list[ToolFilter] = list(filters or [])

    def add(self, f: ToolFilter) -> None:
        self.filters.append(f)

    def apply(self, results: list[SearchResult], query: str) -> list[SearchResult]:
        for f in self.filters:
            results = f.filter(results, query)
        return results

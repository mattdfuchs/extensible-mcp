# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import pytest

from extensible_mcp.types import (
    CallFilterResult,
    CallRequest,
    CallResponse,
    ResponseFilterResult,
    SearchResult,
    ServerLoadRequest,
    ToolRecord,
)
from extensible_mcp.filters import (
    AccessControlFilter,
    CallFilterPipeline,
    DiscoveredToolsFilter,
    FilterPipeline,
    ResponseFilterPipeline,
    ServerLoadAccessControlFilter,
    ServerLoadFilterPipeline,
    SimilarityThresholdFilter,
)


def make_tool(name="test_tool", server="test_server", description="A test tool", input_schema=None):
    qualified = f"{server}__{name}"
    return ToolRecord(
        name=name, qualified_name=qualified, description=description,
        input_schema=input_schema or {"type": "object", "properties": {}},
        server_name=server,
    )


def make_result(tool, score=0.8):
    return SearchResult(tool=tool, score=score)


class TestSimilarityThresholdFilter:
    def test_drops_low_scores(self):
        results = [
            make_result(make_tool("high"), score=0.9),
            make_result(make_tool("medium"), score=0.5),
            make_result(make_tool("low"), score=0.1),
        ]
        f = SimilarityThresholdFilter(min_score=0.4)
        filtered = f.filter(results, "query")
        assert len(filtered) == 2
        assert filtered[0].tool.name == "high"
        assert filtered[1].tool.name == "medium"

    def test_keeps_all_above_threshold(self):
        results = [
            make_result(make_tool("a"), score=0.8),
            make_result(make_tool("b"), score=0.7),
        ]
        f = SimilarityThresholdFilter(min_score=0.3)
        filtered = f.filter(results, "query")
        assert len(filtered) == 2

    def test_removes_all_below_threshold(self):
        results = [
            make_result(make_tool("a"), score=0.1),
            make_result(make_tool("b"), score=0.2),
        ]
        f = SimilarityThresholdFilter(min_score=0.5)
        filtered = f.filter(results, "query")
        assert len(filtered) == 0

    def test_exact_threshold(self):
        results = [make_result(make_tool("exact"), score=0.3)]
        f = SimilarityThresholdFilter(min_score=0.3)
        filtered = f.filter(results, "query")
        assert len(filtered) == 1


class TestAccessControlFilter:
    def test_deny_explicit(self):
        tool = make_tool("delete_repo", "github")
        results = [make_result(tool)]
        f = AccessControlFilter(deny=["github__delete_repo"])
        filtered = f.filter(results, "query")
        assert len(filtered) == 0

    def test_deny_pattern(self):
        results = [
            make_result(make_tool("delete_files", "fs")),
            make_result(make_tool("search_files", "fs")),
        ]
        f = AccessControlFilter(deny_patterns=["*__delete_*"])
        filtered = f.filter(results, "query")
        assert len(filtered) == 1
        assert filtered[0].tool.name == "search_files"

    def test_allow_servers(self):
        results = [
            make_result(make_tool("tool1", "allowed_server")),
            make_result(make_tool("tool2", "blocked_server")),
        ]
        f = AccessControlFilter(allow_servers=["allowed_server"])
        filtered = f.filter(results, "query")
        assert len(filtered) == 1
        assert filtered[0].tool.server_name == "allowed_server"

    def test_empty_allow_servers_allows_all(self):
        results = [
            make_result(make_tool("tool1", "server_a")),
            make_result(make_tool("tool2", "server_b")),
        ]
        f = AccessControlFilter(allow_servers=[])
        filtered = f.filter(results, "query")
        assert len(filtered) == 2

    def test_is_allowed_method(self):
        f = AccessControlFilter(
            deny=["github__delete_repo"],
            deny_patterns=["*__drop_*"],
        )
        assert f.is_allowed("github__create_issue", "github") is True
        assert f.is_allowed("github__delete_repo", "github") is False
        assert f.is_allowed("db__drop_table", "db") is False

    def test_combined_rules(self):
        results = [
            make_result(make_tool("create_issue", "github")),
            make_result(make_tool("delete_repo", "github")),
            make_result(make_tool("drop_table", "db")),
            make_result(make_tool("read_file", "filesystem")),
        ]
        f = AccessControlFilter(
            deny=["github__delete_repo"],
            deny_patterns=["*__drop_*"],
            allow_servers=["github", "filesystem"],
        )
        filtered = f.filter(results, "query")
        assert len(filtered) == 2
        names = {r.tool.name for r in filtered}
        assert names == {"create_issue", "read_file"}


class TestFilterPipeline:
    def test_chains_filters(self):
        results = [
            make_result(make_tool("delete_files", "fs"), score=0.9),
            make_result(make_tool("search_files", "fs"), score=0.8),
            make_result(make_tool("low_score", "fs"), score=0.1),
        ]
        pipeline = FilterPipeline([
            SimilarityThresholdFilter(min_score=0.3),
            AccessControlFilter(deny_patterns=["*__delete_*"]),
        ])
        filtered = pipeline.apply(results, "query")
        assert len(filtered) == 1
        assert filtered[0].tool.name == "search_files"

    def test_empty_pipeline(self):
        results = [make_result(make_tool("a"))]
        pipeline = FilterPipeline()
        filtered = pipeline.apply(results, "query")
        assert len(filtered) == 1

    def test_add_filter(self):
        pipeline = FilterPipeline()
        pipeline.add(SimilarityThresholdFilter(min_score=0.5))
        results = [
            make_result(make_tool("high"), score=0.8),
            make_result(make_tool("low"), score=0.2),
        ]
        filtered = pipeline.apply(results, "query")
        assert len(filtered) == 1


def make_call_request(tool_name="test_server__test_tool", arguments=None, server_name="test_server"):
    return CallRequest(
        tool_name=tool_name,
        arguments=arguments or {},
        server_name=server_name,
    )


class TestCallFilterPipeline:
    @pytest.mark.asyncio
    async def test_allows_when_all_pass(self):
        ac = AccessControlFilter()
        pipeline = CallFilterPipeline([ac])
        result = await pipeline.apply(make_call_request())
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_short_circuits_on_first_rejection(self):
        ac = AccessControlFilter(deny=["test_server__test_tool"])
        ac2 = AccessControlFilter()
        pipeline = CallFilterPipeline([ac, ac2])
        result = await pipeline.apply(make_call_request())
        assert result.allowed is False
        assert "blocked" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_empty_pipeline_allows_all(self):
        pipeline = CallFilterPipeline()
        result = await pipeline.apply(make_call_request())
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_carries_modified_arguments(self):
        """A filter that modifies arguments should carry them forward."""

        class ArgModifier:
            async def check(self, request: CallRequest) -> CallFilterResult:
                new_args = dict(request.arguments)
                new_args["injected"] = True
                return CallFilterResult(
                    allowed=True,
                    tool_name=request.tool_name,
                    arguments=new_args,
                )

        pipeline = CallFilterPipeline([ArgModifier()])
        result = await pipeline.apply(make_call_request(arguments={"a": 1}))
        assert result.allowed is True
        assert result.arguments == {"a": 1, "injected": True}


def make_call_response(
    tool_name="test_server__test_tool",
    arguments=None,
    server_name="test_server",
    content=None,
    is_error=False,
):
    return CallResponse(
        tool_name=tool_name,
        arguments=arguments or {},
        server_name=server_name,
        content=content if content is not None else ["original"],
        is_error=is_error,
    )


class TestResponseFilterPipeline:
    @pytest.mark.asyncio
    async def test_empty_pipeline_passes_through(self):
        pipeline = ResponseFilterPipeline()
        result = await pipeline.apply(make_call_response(content=["hello"]))
        assert result.allowed is True
        assert result.content == ["hello"]
        assert result.is_error is False

    @pytest.mark.asyncio
    async def test_filter_modifies_content(self):
        class Redactor:
            async def check(self, response: CallResponse) -> ResponseFilterResult:
                redacted = [c.replace("secret", "[REDACTED]") for c in response.content]
                return ResponseFilterResult(
                    allowed=True, content=redacted, is_error=response.is_error
                )

        pipeline = ResponseFilterPipeline([Redactor()])
        result = await pipeline.apply(make_call_response(content=["here is the secret value"]))
        assert result.allowed is True
        assert result.content == ["here is the [REDACTED] value"]

    @pytest.mark.asyncio
    async def test_filters_chain_in_order(self):
        """Second filter sees the first filter's modified content."""

        class AppendA:
            async def check(self, response: CallResponse) -> ResponseFilterResult:
                return ResponseFilterResult(
                    allowed=True,
                    content=[c + "-A" for c in response.content],
                    is_error=response.is_error,
                )

        class AppendB:
            async def check(self, response: CallResponse) -> ResponseFilterResult:
                return ResponseFilterResult(
                    allowed=True,
                    content=[c + "-B" for c in response.content],
                    is_error=response.is_error,
                )

        pipeline = ResponseFilterPipeline([AppendA(), AppendB()])
        result = await pipeline.apply(make_call_response(content=["x"]))
        assert result.content == ["x-A-B"]

    @pytest.mark.asyncio
    async def test_short_circuits_on_first_denial(self):
        """A denial stops the chain; later filters do not run."""

        ran: list[str] = []

        class Denier:
            async def check(self, response: CallResponse) -> ResponseFilterResult:
                ran.append("denier")
                return ResponseFilterResult(
                    allowed=False, reason="nope", content=response.content
                )

        class ShouldNotRun:
            async def check(self, response: CallResponse) -> ResponseFilterResult:
                ran.append("after-denier")
                return ResponseFilterResult(
                    allowed=True, content=response.content
                )

        pipeline = ResponseFilterPipeline([Denier(), ShouldNotRun()])
        result = await pipeline.apply(make_call_response())
        assert result.allowed is False
        assert result.reason == "nope"
        assert ran == ["denier"]

    @pytest.mark.asyncio
    async def test_filter_can_flip_is_error(self):
        """A filter can change is_error to surface an issue to the LLM."""

        class FlagAsError:
            async def check(self, response: CallResponse) -> ResponseFilterResult:
                return ResponseFilterResult(
                    allowed=True, content=response.content, is_error=True
                )

        pipeline = ResponseFilterPipeline([FlagAsError()])
        result = await pipeline.apply(make_call_response(is_error=False))
        assert result.is_error is True


class TestAccessControlCallFilter:
    @pytest.mark.asyncio
    async def test_check_allows(self):
        ac = AccessControlFilter()
        result = await ac.check(make_call_request())
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_check_rejects_denied(self):
        ac = AccessControlFilter(deny=["test_server__test_tool"])
        result = await ac.check(make_call_request())
        assert result.allowed is False
        assert "blocked" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_check_rejects_pattern(self):
        ac = AccessControlFilter(deny_patterns=["*__delete_*"])
        result = await ac.check(make_call_request(tool_name="fs__delete_files", server_name="fs"))
        assert result.allowed is False


class TestDiscoveredToolsFilter:
    @pytest.mark.asyncio
    async def test_rejects_undiscovered_tool(self):
        f = DiscoveredToolsFilter()
        result = await f.check(make_call_request())
        assert result.allowed is False
        assert "not been discovered" in result.reason

    @pytest.mark.asyncio
    async def test_allows_discovered_tool(self):
        f = DiscoveredToolsFilter()
        f.register(["test_server__test_tool"])
        result = await f.check(make_call_request())
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_accumulates_across_registrations(self):
        f = DiscoveredToolsFilter()
        f.register(["server__tool_a"])
        f.register(["server__tool_b"])
        result_a = await f.check(make_call_request(tool_name="server__tool_a", server_name="server"))
        result_b = await f.check(make_call_request(tool_name="server__tool_b", server_name="server"))
        assert result_a.allowed is True
        assert result_b.allowed is True


def make_load_request(server_name="test_server", url="https://example.com/mcp"):
    return ServerLoadRequest(server_name=server_name, url=url)


class TestServerLoadFilterPipeline:
    @pytest.mark.asyncio
    async def test_allows_when_all_pass(self):
        f = ServerLoadAccessControlFilter()
        pipeline = ServerLoadFilterPipeline([f])
        result = await pipeline.apply(make_load_request())
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_short_circuits_on_rejection(self):
        f1 = ServerLoadAccessControlFilter(deny_names=["test_server"])
        f2 = ServerLoadAccessControlFilter()  # would allow
        pipeline = ServerLoadFilterPipeline([f1, f2])
        result = await pipeline.apply(make_load_request())
        assert result.allowed is False
        assert "test_server" in result.reason

    @pytest.mark.asyncio
    async def test_empty_pipeline_allows_all(self):
        pipeline = ServerLoadFilterPipeline()
        result = await pipeline.apply(make_load_request())
        assert result.allowed is True


class TestServerLoadAccessControlFilter:
    @pytest.mark.asyncio
    async def test_denies_by_name(self):
        f = ServerLoadAccessControlFilter(deny_names=["evil_server"])
        result = await f.check(make_load_request(server_name="evil_server"))
        assert result.allowed is False
        assert "evil_server" in result.reason

    @pytest.mark.asyncio
    async def test_denies_by_name_pattern(self):
        f = ServerLoadAccessControlFilter(deny_name_patterns=["evil_*"])
        result = await f.check(make_load_request(server_name="evil_corp"))
        assert result.allowed is False
        assert "evil_corp" in result.reason

    @pytest.mark.asyncio
    async def test_denies_by_url_pattern(self):
        f = ServerLoadAccessControlFilter(deny_url_patterns=["http://*"])
        result = await f.check(make_load_request(url="http://insecure.example.com/mcp"))
        assert result.allowed is False
        assert "http://insecure.example.com/mcp" in result.reason

    @pytest.mark.asyncio
    async def test_allows_only_whitelisted_urls(self):
        f = ServerLoadAccessControlFilter(
            allow_url_patterns=["https://github.com/*", "https://internal.corp/*"]
        )
        # Allowed
        result = await f.check(make_load_request(url="https://github.com/org/repo"))
        assert result.allowed is True
        # Denied — not in allowlist
        result = await f.check(make_load_request(url="https://evil.com/mcp"))
        assert result.allowed is False
        assert "does not match" in result.reason

    @pytest.mark.asyncio
    async def test_allows_all_when_no_rules(self):
        f = ServerLoadAccessControlFilter()
        result = await f.check(make_load_request())
        assert result.allowed is True


try:
    import regopy  # noqa: F401
    HAS_REGOPY = True
except ImportError:
    HAS_REGOPY = False

POLICIES_DIR = Path(__file__).parent / "policies"


@pytest.mark.skipif(not HAS_REGOPY, reason="regopy not installed")
class TestRegoPolicyFilter:
    @pytest.mark.asyncio
    async def test_allows_non_matching_tool(self):
        from extensible_mcp.filters import RegoPolicyFilter
        f = RegoPolicyFilter(str(POLICIES_DIR / "deny_delete.rego"))
        result = await f.check(make_call_request(tool_name="fs__search_files", server_name="fs"))
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_denies_matching_tool(self):
        from extensible_mcp.filters import RegoPolicyFilter
        f = RegoPolicyFilter(str(POLICIES_DIR / "deny_delete.rego"))
        result = await f.check(make_call_request(tool_name="fs__delete_files", server_name="fs"))
        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_custom_deny_reason(self):
        from extensible_mcp.filters import RegoPolicyFilter
        f = RegoPolicyFilter(str(POLICIES_DIR / "deny_delete.rego"))
        result = await f.check(make_call_request(tool_name="fs__delete_files", server_name="fs"))
        assert result.allowed is False
        assert "delete operations are not allowed" in result.reason

    def test_raises_without_package_declaration(self):
        from extensible_mcp.filters import RegoPolicyFilter
        with pytest.raises(ValueError, match="must declare a package"):
            RegoPolicyFilter(str(POLICIES_DIR / "no_package.rego"))


class TestUrlPatternHostBinding:
    """`fnmatch`'s `*` crosses `/`, so a pattern meant to constrain the host
    can be satisfied by path content. README recommends `allow_url_patterns`
    as the SSRF defence, so this matters."""

    async def test_host_wildcard_is_not_satisfied_by_path_content(self):
        f = ServerLoadAccessControlFilter(
            allow_url_patterns=["https://*.corp.example/*"]
        )
        result = await f.check(
            make_load_request(url="https://attacker.example/x.corp.example/mcp")
        )
        assert result.allowed is False

    async def test_a_real_subdomain_still_matches(self):
        f = ServerLoadAccessControlFilter(
            allow_url_patterns=["https://*.corp.example/*"]
        )
        assert (await f.check(make_load_request(url="https://api.corp.example/mcp"))).allowed

    async def test_exact_host_pattern_still_matches_a_deep_path(self):
        f = ServerLoadAccessControlFilter(allow_url_patterns=["https://github.com/*"])
        assert (await f.check(make_load_request(url="https://github.com/org/repo"))).allowed

    async def test_a_host_cannot_be_spoofed_through_the_path(self):
        f = ServerLoadAccessControlFilter(allow_url_patterns=["https://github.com/*"])
        result = await f.check(make_load_request(url="https://evil.example/github.com/x"))
        assert result.allowed is False

    async def test_deny_patterns_stay_broad(self):
        """A blacklist must err the other way: still deny on scheme, and now
        also deny on host even where the path would not have matched."""
        f = ServerLoadAccessControlFilter(deny_url_patterns=["http://*"])
        assert (await f.check(make_load_request(url="http://anything/x"))).allowed is False

        f = ServerLoadAccessControlFilter(
            deny_url_patterns=["https://*.evil.example/*"]
        )
        result = await f.check(make_load_request(url="https://a.evil.example/p"))
        assert result.allowed is False

from pathlib import Path

import pytest

from extensible_mcp.types import (
    CallFilterResult,
    CallRequest,
    SearchResult,
    ServerLoadRequest,
    ToolRecord,
)
from extensible_mcp.filters import (
    AccessControlFilter,
    CallFilterPipeline,
    DiscoveredToolsFilter,
    FilterPipeline,
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

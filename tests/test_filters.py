from extensible_mcp.types import SearchResult, ToolRecord
from extensible_mcp.filters import (
    AccessControlFilter,
    FilterPipeline,
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

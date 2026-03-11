import pytest

from extensible_mcp.types import ToolRecord
from extensible_mcp.vector_store import VectorStore


def _make_tool(name, server, description, input_schema):
    qualified = f"{server}__{name}"
    return ToolRecord(
        name=name, qualified_name=qualified, description=description,
        input_schema=input_schema, server_name=server,
    )


_SAMPLE_TOOLS = [
    _make_tool("add_numbers", "math", "Add two numbers together", {
        "type": "object",
        "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
        "required": ["a", "b"],
    }),
    _make_tool("send_email", "comms", "Send an email to a recipient", {
        "type": "object",
        "properties": {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}},
        "required": ["to", "subject", "body"],
    }),
    _make_tool("search_files", "filesystem", "Search for files matching a pattern", {
        "type": "object",
        "properties": {"pattern": {"type": "string"}, "directory": {"type": "string"}},
        "required": ["pattern"],
    }),
    _make_tool("delete_files", "filesystem", "Delete files matching a pattern", {
        "type": "object",
        "properties": {"pattern": {"type": "string"}},
        "required": ["pattern"],
    }),
]

# Module-level store to avoid re-embedding on every test
_store = VectorStore()
_store.index(_SAMPLE_TOOLS)


class TestVectorStore:
    def test_search_returns_results(self):
        results = _store.search("arithmetic addition")
        assert len(results) > 0
        assert results[0].tool.name == "add_numbers"

    def test_search_email(self):
        results = _store.search("send a message via email")
        assert len(results) > 0
        assert results[0].tool.name == "send_email"

    def test_search_files(self):
        results = _store.search("find files in a directory")
        assert len(results) > 0
        assert results[0].tool.name in ("search_files", "delete_files")

    def test_top_k_limits_results(self):
        results = _store.search("tool", top_k=2)
        assert len(results) == 2

    def test_search_empty_store(self):
        store = VectorStore()
        store.index([])
        results = store.search("anything")
        assert results == []

    def test_search_has_scores(self):
        results = _store.search("add numbers")
        assert all(isinstance(r.score, float) for r in results)
        assert all(-1.0 <= r.score <= 1.0 for r in results)

    def test_results_sorted_by_score(self):
        results = _store.search("tool", top_k=4)
        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_add_to_existing_index(self):
        store = VectorStore()
        store.index(_SAMPLE_TOOLS[:2])
        assert len(store._tools) == 2

        new_tool = _make_tool("create_repo", "github", "Create a new GitHub repository", {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        })
        store.add([new_tool])
        assert len(store._tools) == 3

        results = store.search("create a repository on github")
        assert results[0].tool.name == "create_repo"

    def test_add_to_empty_store(self):
        store = VectorStore()
        tool = _make_tool("list_repos", "github", "List GitHub repositories", {
            "type": "object", "properties": {},
        })
        store.add([tool])
        assert len(store._tools) == 1
        results = store.search("repositories")
        assert len(results) == 1
        assert results[0].tool.name == "list_repos"

    def test_add_empty_list_is_noop(self):
        store = VectorStore()
        store.index(_SAMPLE_TOOLS)
        original_count = len(store._tools)
        store.add([])
        assert len(store._tools) == original_count

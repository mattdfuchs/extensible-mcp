# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

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


class TestNonPositiveTopK:
    """top_k is LLM-supplied. A negative one reached numpy as a negative
    slice bound or kth, which returned nearly the whole index -- asking for
    fewer tools got you more."""

    def test_negative_top_k_returns_nothing(self):
        assert _store.search("tool", top_k=-1) == []
        assert _store.search("tool", top_k=-3) == []

    def test_zero_top_k_returns_nothing(self):
        assert _store.search("tool", top_k=0) == []


# -- the fastembed boundary --------------------------------------------------- #
#
# Reported by the maintainer of a downstream fork: the whole catalogue went to
# fastembed as one batch (its default is 256), padded to the longest
# description, and the build peaked around 1 GB for 120 tools against ~260 MB
# resident. Nothing but a memory profiler would notice these regressing, so
# the two settings are pinned where they cross into fastembed.


class TestEmbeddingBoundary:
    def test_texts_go_to_the_model_in_small_batches(self, monkeypatch):
        from extensible_mcp import vector_store as vs_mod

        seen: dict = {}

        class _Model:
            def __init__(self, **kwargs):
                seen["init"] = kwargs

            def embed(self, texts, batch_size=256, **_):
                seen["batch_size"] = batch_size
                import numpy as np
                for _ in texts:
                    yield np.ones(4, dtype=np.float32)

        monkeypatch.setattr(vs_mod, "TextEmbedding", _Model)
        store = vs_mod.VectorStore()
        store.index([ToolRecord(name=f"t{i}", qualified_name=f"s__t{i}", description="d",
                                input_schema={}, server_name="s") for i in range(3)])
        assert seen["batch_size"] == vs_mod.DEFAULT_EMBED_BATCH_SIZE == 8
        assert seen["init"]["enable_cpu_mem_arena"] is False

        vs_mod.VectorStore(embed_batch_size=1, cpu_mem_arena=True).index(
            [ToolRecord(name="t", qualified_name="s__t", description="d", input_schema={}, server_name="s")]
        )
        assert seen["batch_size"] == 1 and seen["init"]["enable_cpu_mem_arena"] is True

    def test_a_batch_size_below_one_is_refused(self):
        with pytest.raises(ValueError, match="at least 1"):
            VectorStore(embed_batch_size=0)

    def test_batching_does_not_change_a_tools_embedding(self):
        """A text's embedding must not depend on what it was batched with, or
        the batch size would be a search-relevance knob rather than a memory one."""
        import numpy as np

        texts = ["send an email to a contact", "create a calendar event " * 30, "list drive files", "x"]
        one = VectorStore(embed_batch_size=1)._encode(texts)
        all_at_once = VectorStore(embed_batch_size=256)._encode(texts)
        assert np.abs(one - all_at_once).max() < 1e-5

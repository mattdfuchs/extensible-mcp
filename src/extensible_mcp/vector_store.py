# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import numpy as np
from fastembed import TextEmbedding

from .types import SearchResult, ToolRecord

_DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"

# fastembed's own default batch is 256, which for a catalogue of ordinary size
# means the whole index is one batch, padded to its longest description, and
# the build's peak memory scales with batch size times padded length squared:
# ~1 GB for 120 tools against ~260 MB resident. Eight is the measured knee --
# the fastest size, 60 MB above the one-at-a-time floor. Search is unchanged:
# a text's embedding does not depend on what it was batched with.
DEFAULT_EMBED_BATCH_SIZE = 8


class VectorStore:
    """In-memory index over the tool catalogue: cosine similarity on normalised
    embeddings from a local ONNX model.

    ``embed_batch_size`` is how many texts go to the model per call (see
    :data:`DEFAULT_EMBED_BATCH_SIZE`). ``cpu_mem_arena`` is ONNX Runtime's CPU
    allocator arena, off by default: with it on, the memory the build peaks at
    stays resident for the life of the process on Linux, where the proxy is
    deployed, rather than returning once the index is built.
    """

    def __init__(
        self,
        model_name: str = _DEFAULT_MODEL,
        *,
        embed_batch_size: int = DEFAULT_EMBED_BATCH_SIZE,
        cpu_mem_arena: bool = False,
    ) -> None:
        if embed_batch_size < 1:
            raise ValueError("embed_batch_size must be at least 1")
        self._model = TextEmbedding(model_name=model_name, enable_cpu_mem_arena=cpu_mem_arena)
        self._batch_size = embed_batch_size
        self._tools: list[ToolRecord] = []
        self._embeddings: np.ndarray | None = None

    def _encode(self, texts: list[str]) -> np.ndarray:
        embeddings = np.array(
            list(self._model.embed(texts, batch_size=self._batch_size)), dtype=np.float32
        )
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        norms = np.where(norms == 0, 1, norms)
        return embeddings / norms

    def index(self, tools: list[ToolRecord]) -> None:
        if not tools:
            self._tools = []
            self._embeddings = None
            return
        self._tools = list(tools)
        texts = [t.embedding_text for t in self._tools]
        self._embeddings = self._encode(texts)

    def add(self, tools: list[ToolRecord]) -> None:
        """Add tools incrementally to the existing index."""
        if not tools:
            return
        texts = [t.embedding_text for t in tools]
        new_embeddings = self._encode(texts)
        self._tools.extend(tools)
        if self._embeddings is None:
            self._embeddings = new_embeddings
        else:
            self._embeddings = np.vstack([self._embeddings, new_embeddings])

    def records(self) -> list[ToolRecord]:
        """Every indexed record, in index order. A copy of the list; the
        records themselves are shared. This is the whole catalogue, which
        static exposure lists after the search pipeline has scoped it."""
        return list(self._tools)

    def search(self, query: str, top_k: int = 5) -> list[SearchResult]:
        if self._embeddings is None or len(self._tools) == 0:
            return []
        if top_k < 1:
            # top_k comes from the LLM. A negative one used to reach
            # argsort/argpartition as a negative slice or kth, which returns
            # *nearly every* tool -- asking for fewer got you more. Zero
            # already meant none; treat anything non-positive the same way.
            return []
        query_vec = self._encode([query])[0]
        scores = self._embeddings @ query_vec
        k = min(top_k, len(self._tools))
        if k >= len(self._tools):
            top_indices = np.argsort(-scores)[:k]
        else:
            top_indices = np.argpartition(-scores, k)[:k]
            top_indices = top_indices[np.argsort(-scores[top_indices])]
        return [
            SearchResult(tool=self._tools[i], score=float(scores[i]))
            for i in top_indices
        ]

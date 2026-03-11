# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

MCP Tool Retrieval Proxy — a middleware layer that sits on top of MCP servers and replaces static tool definitions with semantic search. Instead of sending all tool definitions in the prompt, the LLM gets two meta-tools (`search_tools` and `call_tool`) and discovers tools on demand via vector similarity search.

## Commands

```bash
# Install dependencies (uses uv)
uv sync --group dev

# Run tests
uv run pytest

# Run a single test file
uv run pytest tests/test_vector_store.py

# Run a single test
uv run pytest tests/test_vector_store.py::test_name -v

# Run the server
uv run extensible-mcp --config config.json
```

## Architecture

The proxy is a FastMCP server that connects to downstream MCP servers as a client, indexes their tools, and exposes two meta-tools:

1. **`search_tools(query)`** — embeds the query and runs cosine similarity against the tool index, returns matching tool definitions
2. **`call_tool(tool_name, arguments)`** — proxies the call to the correct downstream server using the qualified name (`{server}__{tool}`)

### Key modules (`src/extensible_mcp/`)

- **`server.py`** — FastMCP server setup, lifespan management, `search_tools`/`call_tool` handler registration. Entry point via `main()`.
- **`client_manager.py`** — Manages stdio connections to downstream MCP servers. Handles connect/reconnect, tool indexing, and proxying `call_tool` requests. Tools are namespaced as `{server_name}__{tool_name}`.
- **`vector_store.py`** — In-memory vector index using `sentence-transformers` (`all-MiniLM-L6-v2`). Encodes tool definitions and does cosine similarity search via normalized dot product.
- **`filters.py`** — Pluggable `FilterPipeline` applied to search results. Includes `SimilarityThresholdFilter` and `AccessControlFilter` (deny lists, deny patterns via fnmatch, server allowlists). Filters implement a `ToolFilter` protocol.
- **`config.py`** — Loads JSON config (same `mcpServers` format as Claude Desktop). Config resolution order: `--config` flag → `EXTENSIBLE_MCP_CONFIG` env var → platform-specific default paths → `./config.json`.
- **`types.py`** — Shared dataclasses: `ServerConfig`, `ToolRecord` (builds its own `embedding_text` from name + description + params), `SearchResult`.

### Testing

Tests use `pytest` with `pytest-asyncio` (auto mode). The mock MCP server in `tests/mock_server.py` provides fake tool definitions for integration tests without real downstream servers.

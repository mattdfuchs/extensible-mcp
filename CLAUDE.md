# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

MCP Tool Retrieval Proxy — a middleware layer that sits on top of MCP servers and replaces static tool definitions with semantic search. Instead of sending all tool definitions in the prompt, the LLM gets three meta-tools (`search_tools`, `call_tool`, `load_mcp_server`) and discovers tools on demand via vector similarity search.

It is also the deterministic enforcement point between the LLM and everything downstream. Every operation crosses a filter pipeline evaluated by code, and where a decision must rest on more than the model's word, a **policy bundle** requires cryptographically signed evidence. The threat model is that anything the LLM produces may be adversary-controlled; see the README's Threat Model section before changing anything on the call path.

## Repo layout

A `uv` workspace of three packages:

- the proxy itself, at the root (`src/extensible_mcp/`)
- `examples/agentic-commerce-demo/` — `extensible-mcp-vc`: the Order Pizza demo, its evidence tools, and the containerized two-org deployment under `deploy/`
- `examples/identity/` — `household-identity`: the wallet service and the `did:web` admin/DID server

Each has its own `tests/` and its own README. The root `uv sync` installs *only* the proxy — not the example packages, and not the policy engines, which are extras.

## Commands

```bash
# Everything, including both example packages and all extras
uv sync --all-packages --all-extras --group dev

# Just the proxy plus pytest and the three engine extras (wasm, rego, cel)
uv sync --group dev

# The three test suites
uv run pytest
uv run --package extensible-mcp-vc pytest examples/agentic-commerce-demo/tests
uv run --package household-identity pytest examples/identity/tests

# A single test
uv run pytest tests/test_vector_store.py::test_name -v

# Run the proxy
uv run extensible-mcp --config config.json

# The containerized demo (build context is the repo root)
docker compose -f examples/agentic-commerce-demo/deploy/docker-compose.yml up --build
```

`regopy` has no wheel on some platforms and builds from source needing git and a C++ toolchain, so a `--group dev` sync can be slow or fail there; the `rego` filter lazy-imports it and errors helpfully.

## Architecture

The proxy is a FastMCP server that connects to downstream MCP servers as a client, indexes their tools, and exposes three meta-tools:

1. **`search_tools(query)`** — embeds the query and runs cosine similarity against the tool index, returns matching tool definitions
2. **`call_tool(tool_name, arguments)`** — dispatches to the correct downstream server by qualified name (`{server}__{tool}`), or to a local tool by bare name
3. **`load_mcp_server(server_name, url)`** — connects to a remote (Streamable HTTP) MCP server at runtime and indexes its tools

### The central invariant

**Every filter runs inside `call_tool_handler`.** Nothing else in the process gates a call. A tool registered directly on the `FastMCP` object is therefore reachable by name and subject to nothing — not access control, not a policy bundle, not even the rule that a tool must have been surfaced by `search_tools`. This was a live hole until `local_tools` closed it; do not reintroduce it by decorating `@server.tool()` after `create_server` returns.

`__` is reserved: it splits a qualified name back into server and tool. `ServerConfig` and `LocalTool` reject a name containing it at construction, and `load_mcp_server` rejects it too — otherwise a server named with one re-parses as a *different* server and escapes per-server routing while still being dispatched.

### Filter pipelines

Four independent pipelines (`FilterPipeline`, `CallFilterPipeline`, `ResponseFilterPipeline`, `ServerLoadFilterPipeline`) gate search, call (request), response, and server-load operations respectively. The only structurally enforced rule is `DiscoveredToolsFilter`: the LLM cannot call any tool it has not previously surfaced via `search_tools` (state is per proxy process, not per MCP session). The other shipped filters (`AccessControlFilter`, `RegoPolicyFilter`, `ServerLoadAccessControlFilter`, `SimilarityThresholdFilter`) are reference implementations — third parties are expected to write their own and inject them via the `extra_search_filters`, `extra_call_filters`, `extra_response_filters`, `extra_load_filters` kwargs on `create_server`. Response filters can inspect or modify tool results on the way back to the LLM (no built-in response filters ship). Custom filters run after the built-ins.

### Policy bundles

A bundle is a directory of four files: `manifest.json` (JSON Schema for the policy's whole closed input), `fetchplan.json` (where each input field comes from — `call`, `config`, `clock`, or a `wallet` lookup you supply), `guidance.json` (a sentence per failable condition, so a denial renders as an explanation), and the rules as either `policy.wasm` (Rego compiled by `opa build -t wasm`) or `checks.cel.json`. The first three are engine-independent; the two engines are interchangeable over them. Seven worked bundles live in `tests/fixtures/`, each with a `PROVENANCE.md`.

Enforcement is a `CallFilter`. `bundle_router` on `create_server` maps each downstream server to the bundle governing it, decided at admission time from proxy-controlled provenance facts — never from tool-supplied metadata — and fails closed on a server it cannot place.

### Key modules (`src/extensible_mcp/`)

Core proxy:

- **`server.py`** — FastMCP server setup, lifespan management, handler registration for the three meta-tools. `create_server(config, *, extra_*_filters=..., bundle_router=..., local_tools=...)` is the public entry point for embedding the proxy; `main()` is the CLI entry and the only place that touches the root logger.
- **`client_manager.py`** — stdio and Streamable HTTP connections to downstream servers, tool indexing, call proxying. Each connection runs a task that owns its transport, because anyio requires the task that entered a cancel scope to exit it and a reconnect happens in the request task. Tokens are presented only to a URL an operator configured for that name.
- **`vector_store.py`** — In-memory vector index using FastEmbed (ONNX runtime) with `all-MiniLM-L6-v2`. Cosine similarity via normalized dot product.
- **`filters.py`** — Filter Protocols (`ToolFilter`, `CallFilter`, `ResponseFilter`, `ServerLoadFilter`), pipeline classes, and the built-in reference filters. The Protocols and request/result dataclasses are re-exported from `extensible_mcp/__init__.py` for third-party imports.
- **`config.py`** — Loads JSON config (same `mcpServers` format as Claude Desktop). Resolution order: `--config` flag → `EXTENSIBLE_MCP_CONFIG` env var → platform-specific default paths → `./config.json`.
- **`types.py`** — Shared dataclasses: `ServerConfig`, `ToolRecord` (builds its own `embedding_text` from name + description + params), `LocalTool`, `SearchResult`, and the per-pipeline request/result pairs (`CallRequest`/`CallFilterResult`, `CallResponse`/`ResponseFilterResult`, `ServerLoadRequest`/`ServerLoadResult`).

Policy-bundle engine:

- **`bundle.py` / `fetchplan.py`** — loads a bundle and assembles the policy's closed input by walking the fetch plan with async, fail-closed resolvers.
- **`policy_engine.py`** — the `PolicyEngine` Protocol both engines implement; the bundle format is engine-plural by design.
- **`wasm_policy.py`** — OPA-compiled Rego evaluated in-process via wasmtime, with the crypto builtins a credential policy needs supplied from Python as host imports, so signature checks run *inside* the policy. The OPA heap is a bump allocator: the heap pointer is captured after instantiation and rewound per query.
- **`cel_policy.py`** — the second engine over the same bundle format, via `cel-python`. A check that does not evaluate to a CEL bool fails closed.
- **`wasm_filter.py`** — the call filters that enforce a bundle: generic `WasmPolicyFilter` and the production `VCPolicyFilter`.
- **`guidance.py`** — renders a denial from the bundle's guidance layer (`render_denial`, exported).
- **`selection.py` / `routing.py`** — which bundle governs a server, and per-call routing.
- **`augment.py`** — search-side augmenter: a governed tool's surfaced schema gains its credential parameters, marked required or required-only-when.
- **`didweb.py` / `wallet_bundle.py` / `issuer.py`** — `did:web` admin key resolution (SSRF-guarded, cached, fail-closed), adaptation of wallet `{token, membership}` bundles into the policy's input shape, and the role→wallet issuer registry.

Engine faults always fail closed and stay distinct from policy denials. When a failure has to reach the LLM, it should arrive as a rendered denial, never as a traceback.

### Testing

Tests use `pytest` with `pytest-asyncio` (auto mode). The mock MCP server in `tests/mock_server.py` provides fake tool definitions for integration tests without real downstream servers. Credential tests build real signed artifacts via `tests/vc_helpers.py` and evaluate them against the actual compiled policy fixtures, on both engines — so a change to the evidence path is tested against the real bundles, not mocks.

CI runs all three suites on 3.11/3.12/3.13.

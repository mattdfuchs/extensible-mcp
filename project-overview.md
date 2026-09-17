# extensible-mcp: Semantic Tool Search and Access Control for MCP

## What it is

A proxy that sits between an LLM (via any MCP client) and downstream MCP servers. It replaces the standard approach of injecting all tool definitions into the LLM's context window with on-demand semantic search, and enforces access control on both search and call paths.

## The problem

As the number of MCP servers grows, so does the number of tool definitions in the prompt. With 5 servers exposing 20 tools each, that's 100 tool definitions consuming context — most irrelevant to the current task. This wastes tokens, degrades model performance, and hits context limits.

Beyond scale, there's a security gap: MCP's tool annotations (`readOnlyHint`, `destructiveHint`) are advisory hints with no enforcement. MCP clients can hide tools from search results, but an LLM that learns a tool name through prompt injection, prior conversation, or training data can still call it directly.

## How it works

The proxy exposes three meta-tools:

- **`search_tools(query)`** — Semantic search over all indexed tools using cosine similarity on embeddings (all-MiniLM-L6-v2). Returns matching tool definitions ranked by relevance.
- **`call_tool(tool_name, arguments)`** — Proxies the call to the correct downstream server. Enforces access control before execution.
- **`load_mcp_server(server_name, url)`** — Dynamically connect to a new MCP server at runtime.

```
LLM  <-->  MCP Client (Claude Desktop, OpenClaw, etc.)
               |
         extensible-mcp proxy (search_tools / call_tool)
               |
         MCP Server(s) (GitHub, filesystem, etc.)
```

The model decides when to search and crafts its own queries — retrieval is model-driven, not automatic. No tool definitions appear in the base prompt; the LLM discovers them on demand.

## Access control

Filter pipelines on both the search and call paths:

- **Search filters**: similarity threshold, access control (deny lists, deny patterns via glob, server allowlists)
- **Call filters**: the same access control rules, enforced again at call time

This is the key security property: **a tool blocked by policy cannot be invoked even if the LLM knows its name.** The search filter hides it from discovery; the call filter blocks execution. Neither alone is sufficient.

### Example config

```json
{
  "mcpServers": {
    "github": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN",
               "ghcr.io/github/github-mcp-server"]
    }
  },
  "filters": {
    "access_control": {
      "deny_patterns": ["*__delete_*"]
    }
  }
}
```

This blocks every GitHub tool with "delete" in its name — including tools added in future server updates — without enumerating them.

## Why not OAuth/JWT?

The OAuth ecosystem has moved past pure issuance-time scoping — Token Exchange (RFC 8693), step-up authentication, signed-header allowlists (Red Hat's `x-authorized-tools` pattern), transaction-token and phantom-token gateway patterns are all deployed. None of it closes the gap:

- `load_mcp_server` adds servers and tools at runtime that didn't exist when any token was issued
- Tool names are proxy-assigned (`{server}__{tool}`), not known to the auth server
- A glob pattern like `*__delete_*` applies to tools that don't exist yet — it's a policy over a shape, not an enumeration
- Scopes and header allowlists are capability grants over tool *names*; none of these mechanisms evaluates the call's actual arguments against a policy, and none is formally grounded

The policy needs to be evaluated at call time against the actual request, not frozen at authentication time. This is fundamentally an ABAC (Attribute-Based Access Control) problem, not an RBAC one.

## Architecture

### Key modules

- **`server.py`** — FastMCP server, lifespan management, handler registration for the three meta-tools. `create_server(config, *, extra_*_filters=…, bundle_router=…, local_tools=…)` is the embedding entry point; `local_tools` registers in-process tools that are discovered and dispatched exactly like downstream ones, through the same call filters.
- **`client_manager.py`** — Manages stdio/HTTP connections to downstream servers, tool indexing, call proxying. Tools namespaced as `{server}__{tool}`.
- **`vector_store.py`** — In-memory vector index using FastEmbed (ONNX runtime). Cosine similarity via normalized dot product.
- **`filters.py`** — Pluggable pipelines for all four paths: search (`ToolFilter`), call (`CallFilter`), response (`ResponseFilter`), and server load (`ServerLoadFilter`). `AccessControlFilter` implements both search and call.
- **`config.py`** — JSON config in Claude Desktop's `mcpServers` format plus `filters` section.
- **`types.py`** — the shared dataclasses: `ServerConfig`, `ToolRecord`, `LocalTool`, `SearchResult`, and the per-pipeline request/result pairs (`CallRequest`/`CallFilterResult`, `CallResponse`/`ResponseFilterResult`, `ServerLoadRequest`/`ServerLoadResult`).

Policy-bundle enforcement:

- **`wasm_policy.py`** — In-process evaluation of OPA-compiled (WASM) Rego policies via wasmtime. The crypto builtins a credential policy needs (`io.jwt.verify_eddsa`, `crypto.sha256`, `key_from_did_key`) are supplied from Python as host imports, so signature checks run *inside* the policy. A builtin error is kept distinct from a `false` verification result — fail closed, never a quiet deny.
- **`cel_policy.py`** — A second engine for the same bundle format: CEL-authored policies (`checks.cel.json`) evaluated via `cel-python`. Reuses the same crypto builtins as thin adapters. Any exception during evaluation — a structural CEL fault or a builtin error — fails closed, with no attempt to distinguish by exception type (CEL doesn't reliably preserve it).
- **`policy_engine.py`** — The `PolicyEngine` Protocol both engines implement (`entrypoints()` / `query()`, OPA's own result shape); the bundle format is engine-plural by design, and a conforming toolchain may target either.
- **`bundle.py` / `fetchplan.py`** — Loads a policy bundle (the enforced rules, in either engine's shape, + `manifest.json` + `fetchplan.json` + optional `guidance.json`) and assembles the policy's closed input by walking the fetch plan with async, fail-closed resolvers (`call` / `config` / `clock` / `wallet`).
- **`wasm_filter.py`** — Call filters that enforce a bundle: the generic `WasmPolicyFilter`, and the production `VCPolicyFilter` (two-VC chain: signed request + conditional authorization, memberships chained to a did:web admin).
- **`selection.py` / `routing.py`** — Which bundle governs a server: operator literal-map overrides layered over an optional Rego classifier, decided from proxy-controlled provenance facts at admission time (never from tool-supplied metadata), then routed per call. Unplaceable servers are refused.
- **`guidance.py`** — Renders a denial from the bundle's guidance layer: a policy's failed check ids become an explanation of which conditions failed and what evidence is still missing. `render_denial` is exported for embedders.
- **`augment.py`** — Search-side augmenter: a governed tool's surfaced schema and description gain its credential parameters, marked required or required-only-when, with the deciding conditions rendered from the bundle's guidance.
- **`didweb.py` / `wallet_bundle.py` / `issuer.py`** — did:web admin key resolution (SSRF-guarded, cached, fail-closed), adaptation of wallet `{token, membership}` bundles into the policy's input shape, and the role→wallet issuer registry.

### Filter architecture

```
Search path:   VectorStore.search() → SimilarityThresholdFilter → AccessControlFilter → [BundleAugmenter] → results
Call path:     CallRequest → AccessControlFilter → DiscoveredToolsFilter → (policy filters) → BundleRouter → downstream server
Response path: tool result → (response filters) → LLM
Server load:   load request → ServerLoadAccessControlFilter → bundle admission (fail closed) → connect + index

Stages in [brackets] are not defaults: `BundleAugmenter` is present only when an embedder
passes it via `extra_search_filters`, as the commerce demo does. The unbracketed stages are
built by `create_server` from config.
```

All four pipelines are extensible — add any filter implementing the protocol.

## Current state

- Working proxy with semantic search, call proxying, and dynamic server loading
- Dual-path access control (search + call) with deny lists, glob patterns, server allowlists; response and server-load pipelines under the same pluggable protocols
- In-process policy engine (OPA-WASM, or CEL) enforcing supplied policy bundles on the call path, signature verification included
- Production Verifiable-Credential enforcement end-to-end: request VC + conditional authorization VC, memberships verified against did:web admin keys, the signed request bound field-by-field to the actual call, credentials stripped before the downstream call
- Per-server bundle selection at admission time, fail closed — a server the proxy cannot positively place is not connected
- Search-side guidance: governed tools surface their credential parameters and when each is required
- 365 tests passing in the proxy's own suite (unit + integration with mock MCP server + end-to-end VC chains against real compiled policy artifacts, on both engines); the two `examples/` workspace packages add 133 and 51
- Example configs for Claude Desktop and OpenClaw, targeting GitHub's MCP server

## ABAC with signed claims

The vision from the Policy as Type research (applying dependent typing to access control) is now implemented in the pipeline, with each role landing where it belongs:

- **Policies as typed propositions**: a policy bundle can be authored by any toolchain that emits the format — including one that derives it from a machine-checked proof, so the policy's properties are proven, not merely tested. The proxy doesn't care which: it consumes the emitted bundle verbatim, hash-pinned, and enforces it in-process, on whichever engine the bundle targets — e.g. a spend tool requires a signed request VC, and above a threshold a co-signed authorization VC, verified at call time.
- **LLM as evidence orchestrator**: the search-side augmenter tells the LLM which credential parameters a governed tool takes and when each is required; the LLM gathers the signed bundles from wallets. Misreading the guidance is a denial, not a security hole.
- **Proxy as runtime enforcer**: the call-side filter assembles the policy's closed input via the bundle's fetch plan, verifies every signature inside the policy, and binds the signed request field-by-field to the call actually being made. The proxy plays the role of a type checker — the call cannot proceed without valid proof. Engine faults fail closed, kept distinct from policy denials.

This separates the LLM's role (orchestrating evidence gathering) from the proxy's role (enforcing policy), avoiding the trap of prompt-based security where the LLM itself is the enforcement mechanism.

Still open: wiring the issuer registry into credential acquisition, and broader evidence sources — push approvals, signed documents, AP2 mandates (SD-JWT rather than JWT-VC, so a new verifier rather than free reuse of the existing one).

## Technical details

- Python 3.11+, built with FastMCP and the MCP SDK
- WASM policy enforcement via wasmtime + joserfc, packaged as an optional extra (`extensible-mcp[wasm]`)
- Embeddings: all-MiniLM-L6-v2 (~22M parameters) via FastEmbed/ONNX, runs on CPU. No PyTorch dependency.
- Config format compatible with Claude Desktop's `mcpServers` format
- Runs as a stdio MCP server; any MCP client can connect to it
- Packaged with hatchling, ready for PyPI publishing via `uv build` / `uv publish`

## Repository

https://github.com/mattdfuchs/extensible-mcp

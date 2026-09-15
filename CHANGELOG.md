# Changelog

Notable changes to extensible-mcp, release by release. The project stays in
semver's `0.x` range deliberately — the public API isn't frozen yet.

## [Unreleased]

**README overhaul: security first**

The root README's "Why" is now two sections, `Why: Security` and
`Why: Extensibility`, in that order — security is the more important half
of this project going forward, not an addendum to the retrieval/extensibility
pitch. `Why: Security` leads with a full narrative walkthrough of the Order
Pizza demo (three signed parties — child, parent, pizza shop — and why an
agent's unsigned word for any of them isn't good enough), rather than a
one-line pointer buried in Examples. Also fixed real staleness found while
auditing every README in the repo: `examples/identity/README.md` claimed a
web approval UI was still deferred when `wallet run --approve web` already
ships and is what the containerized demo actually uses; a `fulfill` tool
description in `pizza_server.py` still said "Tony's Pizza" after the
merchant switch to Domino's.

**Commerce demo: containerized, down to 3 exposed surfaces**

Running the full pizza-negotiation demo used to mean several host shells, a
handful of browser tabs, and a `claude` CLI session — a lot of moving parts
for a demo. `examples/agentic-commerce-demo/deploy/` now exposes exactly
three things: a browser chat window driving the proxy in place of a
terminal `claude` session, a live log stream, and the 2-window passkey
approval page. Everything else (the proxy, the wallet services, the
merchant's MCP server) stays internal to the container network.

- `extensible_mcp_vc.chat_agent.ChatAgent` — a small Anthropic tool-use loop
  against the proxy's own MCP endpoint (the same three meta-tools any MCP
  client would see).
- `examples/console_server.py` — the FastAPI app serving the chat window
  and the log stream (port 7300).
- `ANTHROPIC_API_KEY` is now required for the containerized demo (it drives
  the chat console, not just the merchant's optional LLM clerk).
- The passkey approval page's amount/merchant fields now mirror the live
  pending request (blank when none, read-only, cleared and logged once it
  resolves) instead of carrying static `$15`/`acme` defaults that read as
  an already-active request.
- Stripe is opt-in at *build* time, not just at runtime: the default
  container build no longer installs the `stripe` SDK at all
  (`family.Dockerfile`'s `ENABLE_STRIPE` build arg, default `false`), so a
  released image has no path to any Stripe account regardless of env vars.
  `docker-compose.stripe.yml` is an override that builds the Stripe-enabled
  variant; it still requires your own `STRIPE_API_KEY`.
- The demo's `/logs` stream now filters out per-request access-log noise
  ("`GET /mcp HTTP/1.1" 200 OK`" and friends) so the actual narration
  (policy verdicts, settlement, tool calls) doesn't scroll off behind it.
- The pizzaparlor's merchant switched from Tony's Pizza to Domino's — Tony's
  menu had nothing at or under the $10 solo-approval threshold, so there
  was no way to see the child-only approval path with a real order. Domino's
  "cheese slice" ($4) and "small cheese" ($9) both clear it.
- The chat assistant could reach for `order_pizza`/`spend` (the wallet-VC
  rail, approved via the kid/parent wallet *pages*) instead of the
  negotiate/invoice/passkey path — and those wallet pages aren't published
  in this containerized deployment, so a request through either tool had
  nowhere to be approved and just sat there, indistinguishable from a hang.
  Fixed structurally, not just with a system-prompt instruction: when
  `HIDE_WALLET_GATED_TOOLS=true` (set by the container's entrypoint;
  unset for the manual multi-terminal walkthrough), `family_proxy_server.py`
  hides those two tools from `search_tools` outright, so
  `DiscoveredToolsFilter` makes them structurally uncallable rather than
  merely discouraged.
- Fixed a startup race that could take the whole family container down:
  `console_server.py` made exactly one attempt to connect to the proxy over
  MCP, and if the proxy hadn't finished binding yet (timing varies with
  system load), the attempt failed and — because the failure surfaced as a
  `BaseExceptionGroup` from the `mcp` client's own task group, which
  `except Exception` doesn't catch — crashed the container instead of
  retrying. Now retries with backoff and logs each attempt.

## [0.2.0] - 2026-09-10

The "v2" release. Everything below is new relative to 0.1.0, which was just
the base proxy — none of it existed yet at that tag.

**The policy-bundle engine (new)**

A bundle is a directory of artifacts — a policy plus `manifest.json` (the
closed input's JSON Schema), `fetchplan.json` (where each input field comes
from), and an optional `guidance.json` (human-facing denial text) — that a
`CallFilter` enforces against signed Verifiable-Credential evidence rather
than raw call arguments. New modules:

- `bundle.py` / `policy_engine.py` — `PolicyBundle` and the `PolicyEngine`
  Protocol, with two implementations: `OpaWasmPolicy` (compiled OPA/Rego,
  evaluated in-process via `wasmtime`, with pluggable crypto host builtins —
  `io.jwt.verify_*`, `crypto.sha256`) and `CelPolicy` (CEL, pure Python via
  `cel-python`) — proving the bundle format is engine-plural rather than
  tied to one supplier's toolchain. `PolicyBundle.load(..., engine="rego" |
  "cel")` overrides the default file-presence sniffing (`policy.wasm` vs
  `checks.cel.json`); raises `FileNotFoundError` if the forced engine's
  artifact is missing rather than silently falling through.
- `fetchplan.py` — assembles the policy's closed input by walking the
  bundle's fetch plan (`call` / `config` / `clock` / `wallet` sources);
  fail-closed if a required value can't be produced.
- `guidance.py` — renders a denial's failed-check ids into human-facing text
  from the bundle's `guidance.json`.
- `wasm_filter.py` (`VCPolicyFilter` / `WasmPolicyFilter`) — the `CallFilter`
  that ties it together: splits credential fields from native arguments,
  assembles the input, evaluates `allow`, and either strips the credentials
  and passes the call through or denies with the policy's reason.
- `wallet_bundle.py` (`WalletBundleAdapter`) — bridges household-identity's
  wallet-issued `{token, membership}` bundles into a policy's expected input
  shape (JWS decode, cents normalization, membership harvesting).
- `didweb.py` (`DidWebResolver`) — resolves `did:web` admin DIDs to their
  Ed25519 JWK for membership-chain verification; only resolves DIDs already
  in the trusted-admin set (an SSRF guard, not a substitute for the policy's
  own issuer check) and fails closed on a resolution error.
- `issuer.py` (`IssuerRegistry`) — role → wallet mapping, so a policy naming
  a role ("a parent must sign") doesn't hard-code which wallet fulfills it.
- `selection.py` / `routing.py` (`LayeredBundleSelector`, `BundleRouter`) —
  stage-one selection of which bundle governs a server (an operator literal
  map layered over an optional Rego classifier) and stage-two per-call
  dispatch to that bundle's filter. A refused server is never connected —
  for both statically configured servers **and** ones loaded at runtime via
  `load_mcp_server`, which now goes through the same admission gate.
- `augment.py` (`BundleAugmenter`) — a search-side `ToolFilter` that injects
  a governed tool's required credential fields (typed from the manifest,
  worded from `guidance.json`, ordered by dependency) into its schema before
  the LLM ever sees it.

**A fourth filter pipeline: response filters (new)**

`ResponseFilter` / `ResponseFilterPipeline` (`filters.py`, `types.py`'s new
`CallResponse` / `ResponseFilterResult`) let filters inspect, modify, or
replace a tool's result on its way back to the LLM — wired into
`create_server` via `extra_response_filters`. No built-in response filter
ships; useful for redacting secrets a downstream server leaks back, or
scrubbing prompt-injection content from scraped pages.

**Dependencies**

- `regopy` moved from a hard base dependency to an optional `rego` extra
  (alongside new `wasm` and `cel` extras) — it ships no wheels for some
  platforms and needs a C++ toolchain to build from source, which was
  needlessly required even for deployments that never use `rego_policy`.

**New examples**

- [`examples/agentic-commerce-demo/`](examples/agentic-commerce-demo/) — a
  two-organization commerce demo built on the policy-bundle engine above:
  wallet-issued Verifiable Credentials gate spends at the MCP call boundary,
  and a separate WebAuthn/passkey rail binds human approval to
  merchant-signed invoices through negotiation, settlement (mock or Stripe
  test-mode), and signed fulfillment. Ships a Docker Compose setup
  (`deploy/`) for a two-container demo of both organizations' agents.
- [`examples/identity/`](examples/identity/) — the wallet and `did:web`
  admin server backing the commerce demo's credential chain.
- Both are `uv` workspace members of this repo (see the root
  `pyproject.toml`'s `[tool.uv.workspace]`) rather than separate checkouts —
  `uv sync --all-packages` resolves everything from one lockfile.

**Fixed**

- `OpaWasmPolicy`'s EdDSA verification now accepts both `"Ed25519"`
  (RFC 9864) and `"EdDSA"` (RFC 8037) JOSE header names for the same
  signature scheme, for interop across toolchains that pick either
  convention.
- `CelPolicy.query()` now preserves the `allow ⟺ failed_checks == []`
  invariant that Rego bundles get structurally, which it had missed on a
  real production bundle's repro case.

**Unchanged**

- `RegoPolicyFilter` (the `rego_policy` config option — one `.rego` file,
  no bundle, no manifest, no signed evidence) is untouched by any of the
  above. It interprets raw Rego source at call time against
  `{tool_name, arguments, server_name}` and only defines `allow` /
  `deny_reason`; it does not implement `PolicyEngine` and has no CEL
  equivalent. Reach for the bundle engine, not this option, if you need CEL
  or verified credentials.

## [0.1.0] - 2026-04-30

First public release: dynamic MCP server loading, RAG-based tool retrieval,
and three filter pipelines (search / call / server-load) — access control,
the single-file `rego_policy` option, server-load whitelisting, and the
structural "can't call what you haven't searched for" guarantee.

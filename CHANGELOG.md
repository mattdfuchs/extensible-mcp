# Changelog

Notable changes to extensible-mcp, release by release. The project stays in
semver's `0.x` range deliberately — the public API isn't frozen yet.

## [Unreleased]

## [0.3.0] - 2026-09-16

**Added: `local_tools` — one calling convention for every tool**

`create_server(..., local_tools=[LocalTool(...)])` registers in-process tools
alongside the downstream ones. They are indexed for `search_tools`, invoked
through `call_tool`, and pass through the same `CallFilterPipeline` as a
downstream tool — `DiscoveredToolsFilter`, access control, policy bundles, all
of it.

This closes a hole rather than adding a convenience. The commerce demo used
to register its evidence tools (`request_action_vc`,
`request_authorization_vc`, `request_invoice_approval`,
`record_fulfillment`) directly on the FastMCP object after `create_server`
returned. Every filter in this project runs inside `call_tool_handler`, so a
tool registered that way was reachable by name and subject to nothing — not
even the rule that a tool must be surfaced by `search_tools` before it can be
called. There is no principled reason an in-process tool needs less scrutiny
than a downstream one; where the code happens to live is not a security
boundary. It also cost the model real tool-call rounds, which is how the hole
was found: the chat agent had to be told that some tools were called one way
and some another.

`ServerConfig` and `LocalTool` both now reject a name containing `__` at
construction. That separator splits a qualified name back into server and
tool, so a server named with one re-parsed as a *different* server —
escaping per-server bundle routing and `allow_servers` while still being
dispatched. `load_mcp_server` rejects it too.

**Security fixes from a pre-release review**

An independent read of the tree before release turned up five issues that are
fixed here. Each was reproduced or measured, not just read.

- **A stored token could be sent to any URL the model chose.** Tokens are
  keyed by server *name*, but `load_mcp_server` lets the LLM supply both the
  name and the URL — so naming a configured server and pointing it at an
  attacker's host handed over that server's bearer token. A connection now
  presents a credential only when an operator named that exact URL for that
  name in the config file; otherwise it connects without one and logs why.
- **Host wildcards in `allow_url_patterns` were bypassable.** `fnmatch`'s `*`
  crosses `/`, so `https://*.corp.example/*` was satisfied by
  `https://attacker.example/x.corp.example/mcp` — the host constraint met by
  path content, in the control the README recommends as the SSRF defence.
  Both lists now also match the pattern's host against the URL's parsed
  host: the allow list narrows, the deny list broadens.
- **The OPA wasm heap grew without bound.** `opa_malloc` is a bump allocator
  and nothing frees, so every query's data, input, builtin results and
  result value accumulated: measured at 2 → 509 pages (33 MB) over 3000
  queries, linear. A loop of denied calls to a governed tool would exhaust
  memory, and SECURITY.md lists proxy DoS as in scope. The heap pointer is
  captured after instantiation and rewound at the top of each query;
  `_read_cstr` no longer copies all of memory per read.
- **Secrets reached image layers.** Both Dockerfiles `COPY` the repo root,
  and the `.dockerignore` files' "never bake secrets" section listed only
  `.env`. Inspecting the built image found `examples/tokens` and the
  merchant's private Ed25519 key in `/repo`: gitignored, so never in git,
  but `COPY` takes the working tree. `**/tokens`, `**/*.key`, `**/*.jwk` and
  `**/keys` are now excluded from both.
- **The family control plane was reachable from the merchant container.** The
  wallets and the policy proxy bound `0.0.0.0` on a shared compose network,
  so the merchant could drive the proxy as an MCP client or POST a wallet's
  `/sign/request` with its own prompt text and callback URL — and received
  the family's whole `.env`, `STRIPE_API_KEY` included. All three now bind
  loopback (every consumer is in the same container) and the merchant's
  `STRIPE_API_KEY` is blanked. The approval service still has to be
  reachable, since its passkey pages are published to the host;
  `deploy/README.md` now has a section stating exactly what the container
  boundary does and does not enforce, rather than implying it is the org
  boundary.

**Correctness: failures that escaped, and inputs that passed**

- A stdio reconnect after a failed call ran in the request task, but the
  transport's cancel scopes were entered in the lifespan task. The retry
  appeared to work — the cross-task error was swallowed — but the child was
  never reaped and `close_all()` from the lifespan task then hung forever, so
  the proxy could no longer shut down. Each connection now runs a task that
  owns its transport, so connect and close are safe from anywhere.
- A credential token whose payload decoded to `[]`, `"text"` or `5` raised
  `AttributeError` out of the wallet adapter, past the filter's handler and
  the guidance layer, reaching the LLM as a traceback. So did
  `{"vc": "notadict"}`. Both are now rendered denials.
- An unreachable `did:web` admin raised `DidResolutionError`, which the filter
  does not catch; the membership lookup is a fetch-plan source, so it now
  raises `FetchError` and renders as a denial.
- A CEL check evaluating to a non-empty string, map or list passed, because
  the result was read with `bool()`. A check that was meant to compare
  something but returned the thing instead therefore passed unconditionally,
  and only ever in the direction that allows. Anything but a CEL bool now
  fails closed.
- A negative `top_k` — LLM-supplied, unvalidated — reached numpy as a
  negative slice bound and returned nearly the whole index: asking for fewer
  tools got you more. Non-positive now returns none.
- The bundle selector's literal map is an exact-string lookup on a URL, so
  `https://Evil.example/mcp/` missed an entry banning
  `https://evil.example/mcp`. Scheme and host are case-folded and a trailing
  slash dropped, per RFC 3986.
- A refused downstream connection surfaced as "unhandled errors in a
  TaskGroup (1 sub-exception)"; exception groups are now unwrapped to their
  leaves before the message reaches the LLM.
- Two concurrent `load_mcp_server` calls for one name both passed the
  "already connected" check, because a network round-trip separated it from
  the registration. `connect_url` now holds a lock across both.
- `logging.basicConfig` ran at import, reconfiguring the root logger of any
  application embedding the proxy. It now runs in `main()`.
- The demo's `/settle` resolved an approved invoice by `(merchantId,
  amountCents)` and took the most recent match, so two approved invoices
  from one merchant for the same total meant the policy could verify one and
  settlement charge the other. The invoice's `nonce` now names the record,
  `charge_invoice` carries it, and the proxy's invoice adapter refuses a
  nonce that is not the one inside the signed invoice.
- Smaller, in the demo and identity packages: `/settle` no longer blocks the
  event loop (and with it the approval page's polling) while a synchronous
  payment rail runs; the console's connect-retry no longer swallows a
  shutdown's cancellation, and no longer dies when tearing down a
  half-opened transport; the entrypoint waits for the proxy to accept
  connections instead of sleeping two seconds; and the wallet holds a
  reference to its async-approval task, which asyncio could otherwise
  collect while it waited on a human.

**Packaging and CI**

- `readme` was unset, so the built wheel had no long description — a PyPI
  page would have rendered blank.
- `httpx` is imported at module scope by `client_manager` and `cryptography`
  by a wasm host builtin; both arrived transitively and are now declared
  (the latter on the `wasm` extra).
- The sdist carried only the package: no README, no LICENSE text, no tests.
  It now includes `tests/`, README, CHANGELOG, LICENSE, SECURITY and
  CONTRIBUTING.
- The `dev` group listed a hand-copied subset of the three engine extras; it
  now depends on `extensible-mcp[wasm,rego,cel]`, with `[tool.uv.sources]`
  resolving that self-reference to the workspace.
- CI installed with `uv sync --group dev`, which never installs the two
  workspace members, and ran only the root suite — so 165 tests in the
  commerce-demo and identity packages had never run in CI. All three suites
  now run, and the pinned actions are current.
- The README documented `regopy` as installed by default, true only for a
  checkout via the dev group; the extras are now documented, and the
  `RegoPolicyFilter` import error names the extra rather than a group.

**Repo hygiene**

`cd mcp-alternative` appeared in both deploy READMEs, the RUNBOOK, the
compose file and both Dockerfiles — that is a local working directory name,
and a clone lands in `extensible-mcp/`, so those steps failed for anyone
following them. `.gitignore` no longer names a private branch. Docstrings
that referred to numbered seams, lettered deliverables and "the fork" —
private working vocabulary — now say the thing itself.

**Removed: the self-asserted spend rail**

The approval page had a "Send a test request ($15 to acme)" button that
conjured a $15 spend approval from nothing, and `POST /request` behind it. The
WebAuthn challenge on that rail was a pure function of the terms —
`legov1|spend|{tool}|{amountCents}|{merchant}` — with nothing per-transaction
in it, so one passkey assertion authorized unlimited identical calls. With the
Stripe downstream enabled that meant one approval, many charges, since it
minted a fresh `uuid4()` idempotency key per call.

The invoice rail does not have this shape: its challenge is taken over a whole
merchant-signed invoice, the invoice carries a `nonce`, and settlement and
fulfilment both key on it. So rather than bolt a replay cache onto the weaker
design, the rail is gone: the button, `POST /request`,
`request_webauthn_approval`, `spend_challenge()`, and the WebAuthn wire
adapter. `payments__spend` survives, rerouted onto `family_spend_prod` — the
wallet-VC rail that binds signed intent to the call field by field — so the
`boot_demo.py` walkthrough is unaffected.

An approval request can now only be created by a merchant-signed invoice,
never from the page. The `family_spend_webauthn` bundle stays in
`tests/fixtures/` with its tests, unwired, as the artifact to fix: reinstating
the rail means giving its challenge a per-approval nonce, which changes the
canonical string and so needs the Rego and the compiled wasm re-issued
together. This also removes `legov1` from all shipped Python.

**Removed: the pre-bundle enforcement path (`VCCallFilter`)**

The demo package carried two implementations of the same job. `VCCallFilter`
verified a credential chain in hand-written Python; the policy-bundle engine
does it declaratively. Only the second one compared the signed evidence to
the call it was authorizing — the hand-coded filter checked signatures,
chain and freshness, then forwarded whatever arguments it was given, so a
credential signed for $1 would pass a call for $500. The shadow harness had
found this and a test asserted it as expected behaviour, which is what kept
it invisible.

None of it had ever shipped: `v0.1.0` is the only released tag and contains
none of this package. So rather than patch a path the bundle engine already
supersedes, it is gone — `vc_filter.py`, `shadow.py`, `extend.py`
(`extend_server`), `schema_augmenter.py`, `examples/proxy_server.py`,
`examples/price_tier_filter.py`, and their tests. Every gated call now goes
through a bundle, and the threshold that used to live in a Python filter is
a tier in the policy. `examples/README.md` is rewritten around the two
surviving entry points: `boot_demo.py` for a one-command scripted run, and
`family_proxy_server.py` for the real thing with wallets.

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

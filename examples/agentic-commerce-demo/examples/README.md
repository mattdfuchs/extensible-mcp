# Family-network demo

Two wallets (kid, parent), one DID admin, two mock backends, the proxy
in the middle. The kid asks the LLM to do something on the household's
account; the LLM has to collect signed credentials from both wallets
before the proxy will let the call through.

Two scenarios ship out of the box:

- **`payments__spend`** — the original toy demo. The kid spends money
  at a vendor; debits a running balance.
- **`pizza__order_pizza`** — a more concrete scenario built on the same
  gating: the kid orders a pizza from a known store; the order is
  recorded to a log file you can `tail -f` in a separate terminal so a
  demo audience can watch orders arrive in real time. See
  [`n8n/README.md`](n8n/) for an end-to-end walkthrough with an LLM
  driving the order via n8n's AI Agent.

The mechanics below describe the spend demo because it's the simplest;
pizza-ordering is the same shape with a different tool call.

Scope note: this walkthrough is the **original two-VC wallet path**, run via
`proxy_server.py` with `VCCallFilter` as the authority. It is not the current
commerce demo — that one moves the decision into a policy bundle and adds
passkey approvals, merchant-signed invoices, and settlement, gating three
tools at once via `family_proxy_server.py`. See [`../deploy/`](../deploy/) for
it, and [the package README](../README.md#read-this-first-two-enforcement-paths-three-rails)
for how the two relate. Both still work; this is the simpler one to run by
hand in three terminals.

## What gets gated

The proxy is configured with
`gated_tools: ["payments__spend", "pizza__order_pizza"]`. Calling either
of those tools requires both:

1. A signed **ActionRequest** VC from the kid's wallet (kid's `did:key`
   issuer), with a current FamilyMembership VC issued by the family admin
   (`did:web:family.example.com`).
2. A signed **ActionAuthorization** VC from the parent's wallet (parent's
   `did:key` issuer), bound to the request by `jti` and SHA-256 hash of the
   request's compact JWS, plus the parent's own FamilyMembership VC.

`balance` is not gated and can be called without VCs.

## Setup

From this package's root (`examples/agentic-commerce-demo`):

```bash
uv run python examples/setup.py
```

This creates a `workspace/` directory with:

- `keys/` — admin, kid, parent JWK private keys (chmod 0600)
- `public/.well-known/did.json` — admin DID document
- `memberships/{kid,parent}.jwt` — admin-signed membership credentials
- `vc-config.json` — proxy-side VC configuration (gated tools, trusted
  admin DIDs, the admin's DID document embedded so the proxy doesn't need
  real HTTPS resolution)
- `config.json` — extensible-mcp config that launches both
  `payments_server.py` and `pizza_server.py` as stdio downstream servers
- `pizza-orders.log` — created on first pizza order; `tail -f` to watch

## Run

In three separate terminals (the exact commands are printed by setup.py):

```bash
# 1. Kid's wallet on :7401
uv run --package household-identity wallet run \
    --keys-dir workspace/keys --label kid --port 7401 \
    --membership-path workspace/memberships/kid.jwt

# 2. Parent's wallet on :7402
uv run --package household-identity wallet run \
    --keys-dir workspace/keys --label parent --port 7402 \
    --membership-path workspace/memberships/parent.jwt

# 3. The proxy (stdio MCP server)
uv run python examples/proxy_server.py \
    --config workspace/config.json --vc-config workspace/vc-config.json
```

Point an MCP-aware client (Claude Desktop, an MCP test harness) at the
stdio command in (3).

## The walkthrough

Kid sits at the kid wallet's terminal. The LLM (running in the MCP client)
is told: "spend $15 at the pizza shop." It then:

1. `search_tools("spend money at a vendor")` — the proxy returns the
   `payments__spend` tool with an augmented schema. The schema now lists
   `vc_request` and `vc_authorization` as required parameters and the
   description explains how to obtain them.

2. `request_action_vc(action="spend", details={"amount": 15.0, "vendor":
   "pizza"})` — the proxy POSTs to the kid wallet at :7401. The kid
   wallet prints the request and prompts on stdin. Kid types `y`. The
   wallet signs and returns a bundle `{token, membership}`.

3. `request_authorization_vc(request=<kid's bundle>, scope={"max_amount":
   20.0})` — the proxy POSTs to the parent wallet at :7402. The parent
   wallet prints the request the kid signed and prompts on stdin. Parent
   types `y`. The wallet signs an ActionAuthorization VC bound to the
   kid's request and returns its own bundle.

4. `call_tool("payments__spend", {amount: 15.0, vendor: "pizza",
   vc_request: <kid bundle>, vc_authorization: <parent bundle>})` — the
   proxy's VCCallFilter:
   - verifies both VC signatures against the issuer `did:key`s
   - checks the authorization is bound to this request (jti + hash)
   - verifies both membership VCs against the admin's `did:web` key
   - checks the temporal validity of all three credentials

   On success, the VC arguments are stripped and `payments__spend(amount,
   vendor)` is forwarded to the downstream server. The kid sees: "OK.
   Spent $15.00 at pizza. New balance: $85.00."

If kid types `n` at step 2 (or parent at step 3), the meta-tool returns
an error and the call never reaches the payments backend.

## Cleanup

`rm -rf workspace/`. All state is in there.

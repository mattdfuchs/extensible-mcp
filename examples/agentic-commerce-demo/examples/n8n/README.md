# n8n pizza-ordering workflow

A worked example of driving the family-network VC chain from an n8n AI
Agent. The kid says "order a large pepperoni from Dominos", the LLM
discovers the gated tool, collects a request VC from the kid's wallet
and an authorization VC from the parent's wallet, the proxy verifies
the chain, and `pizza__order_pizza` runs.

## Prerequisites

1. **Demo workspace initialized.** From this package's root (`examples/agentic-commerce-demo`):
   ```bash
   uv run python examples/setup.py
   ```
   This creates `workspace/` with keys, memberships, `config.json`, and
   `vc-config.json` (with `callback_base_url` already set for async
   wallet approvals).

2. **Wallets running.** Two terminals, kid on `:7401` and parent on
   `:7402` — the exact commands are printed by `setup.py`.

3. **Proxy running with HTTP transport.** A third terminal:
   ```bash
   uv run python examples/family_proxy_server.py \
       --vc-config workspace/vc-config.json \
       --host 0.0.0.0 --port 7400
   ```
   `0.0.0.0` matters — n8n is in a Docker container and reaches the
   proxy via `host.docker.internal:7400`, which only works if the
   proxy binds to a non-loopback interface.

4. **Pizza orders log tailed.** A fourth terminal:
   ```bash
   tail -f workspace/pizza-orders.log
   ```
   Order confirmations land here once the chain completes.

5. **n8n running.** Easiest is a dedicated container so workflows
   don't collide with anything else you have:
   ```bash
   docker run -d --name extensible-mcp-n8n \
     -p 5679:5678 \
     -e N8N_SECURE_COOKIE=false \
     -e N8N_AUTH_COOKIE=n8n-auth-vc \
     -v extensible_mcp_n8n_data:/home/node/.n8n \
     n8nio/n8n:latest
   ```
   Visit `http://localhost:5679`, complete the owner setup, add an
   Anthropic credential (or OpenAI; the Anthropic Chat Model node
   wires up either with a small change to the LLM node).

## Workflow shape

Five nodes:

| Node | Type | Wires to |
|---|---|---|
| **When chat message received** | Chat Trigger | → AI Agent (main) |
| **AI Agent** | AI Agent (Tools Agent) | output → end |
| **Anthropic Chat Model** | LM Chat Anthropic | → AI Agent (ai_languageModel) |
| **Simple Memory** | Memory Buffer Window | → AI Agent (ai_memory) |
| **MCP Client** | MCP Client Tool | → AI Agent (ai_tool) |

### MCP Client configuration

- **Transport:** HTTP Streamable
- **Endpoint:** `http://host.docker.internal:7400/mcp`
- **Include tools:** all (default)

### AI Agent system message

```
You help a kid order food on the household's account. Available pizza
vendors include Dominos, Tony's Pizza, and Pizza Hut.

This server hides downstream tools behind a discovery step. The only
tools you can invoke directly are the meta-tools `search_tools`,
`call_tool`, `request_action_vc`, and `request_authorization_vc`.
Tools whose name starts with `pizza__` (or any other `server__`
prefix) must be surfaced via `search_tools` *before* you can call
them through `call_tool` — the proxy enforces this. A single search
returns up to 5 matching tools and registers all of them as callable,
so one well-aimed query at the start of the conversation is enough.

Workflow for an order:

1. `search_tools(query="pizza ordering menu")` once, to surface the
   pizza backend's tools (you'll get back `pizza__list_stores`,
   `pizza__get_menu`, `pizza__order_pizza`).
2. `call_tool(tool_name="pizza__get_menu", arguments={"store": "Dominos"})`
   to look up unit prices.
3. Compute the total as unit_price × quantity.
4. `request_action_vc(action="order_pizza", details={...})` to get
   the kid's consent VC.
5. If total > $10, also call `request_authorization_vc(request=<kid
   bundle>, scope={"max_total": <total>})` for the parent's VC. If
   total ≤ $10, skip this step.
6. `call_tool(tool_name="pizza__order_pizza", arguments={pizza_type,
   store, address, quantity, total, vc_request: <kid bundle>,
   vc_authorization: <parent bundle if you obtained one>})`.

Household policy on `pizza__order_pizza`:

- Total ≤ $10: skip step 5; the kid's VC alone is enough.
- $10 < total ≤ $200: include step 5; the parent's VC is required.
- Total > $200: don't try the order. Apologize to the kid and
  suggest a smaller order.

If the policy rejects an attempted call for missing parental
authorization, retry once with the parent's VC. Don't fabricate VCs;
the proxy verifies them cryptographically and missing or invalid VCs
will be detected.

The kid's default delivery address is 123 Main St unless the user
gives a different one.
```

### Try it — three scenarios that exercise each policy tier

**Tier 1 (under $10, no parent needed):**
> I want a cheese slice from Dominos.

You should see a kid-wallet stdin prompt, no parent prompt, the
proxy trace ending in `[POLICY] ✓ pizza__order_pizza passes`, and a
new line in `pizza-orders.log` with total $4.00.

**Tier 2 ($10–$200, parent required):**
> Order a large pepperoni from Dominos.

Both wallets prompt; total $15.00; `[POLICY]` line shows the parent
threshold check, and an order lands in the log.

**Tier 3 (over $200, hard cap):**
> Order 20 large pepperoni pizzas from Dominos.

Total $300.00, which satisfies no tier of the governing policy — the
solo tier caps at $10 and the full chain at $200 — so the call is denied
however much evidence is attached. The LLM should report back that the
household policy rejected the order.

## Workflow JSON

`workflow.json` in this directory is a template you can import via
**Workflows → Import from File** in the n8n UI. It captures the node
shape and the system message but uses placeholder credential and node
IDs — n8n will prompt you to remap or recreate the Anthropic credential
on import. If the version drift bites (n8n's workflow schema changes
across releases), the cleanest path is to build the workflow once in
the UI from this README, then **Workflows → Download** to replace this
file with your canonical export.

## Async wallet approvals — what makes the demo realistic

`vc-config.json` ships with `callback_base_url` set, so the proxy
runs in async mode: each wallet POST returns 202 immediately and the
proxy awaits the signed bundle on a Future that the wallet's callback
resolves. The wallet's stdin prompt still drives approval in v0.1, but
the architecture is now what real production flows need — a parent
who isn't at the terminal can approve via whatever UI gets bolted on
later (web form, Telegram bot, push notification) without changing
the proxy or the LLM contract.

The proxy waits up to `callback_timeout_seconds` (default 150s, set
in `vc-config.json`) for the callback. If the parent isn't around in
time, the LLM gets a structured error and can offer to retry.

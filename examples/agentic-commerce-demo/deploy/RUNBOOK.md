# Runbook: bringing the two-org demo up

Moving pieces: 2 containers (family, pizzaparlor) and 4 browser windows —
chat, live log, and the passkey page open twice (one window per role, child
and parent). A fifth URL, the audit view, is optional. No terminal session on
the host beyond `docker compose` itself; everything else lives inside the
containers.

## 0. Prerequisites

- Docker running.
- A checkout of `extensible-mcp` — the compose build context is the repo
  root; `household-identity` and this demo live inside it as workspace
  members (`examples/identity`, `examples/agentic-commerce-demo`).
- An `ANTHROPIC_API_KEY` (see step 1) — the chat console needs it to work at
  all, not just for a nicer merchant clerk.
- No stale demo processes holding ports 7300 or 7500 (stop any old terminal
  runs of the console / approval service first).

## 1. Environment (required)

Put the keys in **`examples/agentic-commerce-demo/.env`** (gitignored,
never baked into images; compose injects it into both containers at start —
no exports needed):

```sh
ANTHROPIC_API_KEY=sk-ant-...   # required: drives the chat console's agent
                                #   loop, and doubles as Domino's clerk
SETTLEMENT=stripe              # invoice rail charges Stripe test mode —
STRIPE_API_KEY=sk_test_...     #   needs the Stripe-enabled build, step 2
```

Without `ANTHROPIC_API_KEY`, the containers still start, but the chat
window returns an error on the first message — there's no fallback path for
the thing driving the whole demo, unlike the merchant's clerk (which falls
back to a deterministic list-price responder without a key).

`SETTLEMENT`/`STRIPE_API_KEY` are inert on the default build below — it
doesn't have the `stripe` SDK installed at all, so there's no path to any
Stripe account, yours or anyone else's. See step 2 for the opt-in build.

Changes to `.env` take effect on the next `up` (restart the containers — no
rebuild needed).

## 2. Start the containers

```sh
cd extensible-mcp
docker compose -f examples/agentic-commerce-demo/deploy/docker-compose.yml up -d --build
```

This build never installs the Stripe SDK — the mock settlement rail is the
only one reachable. If you've put `SETTLEMENT=stripe` + your own
`STRIPE_API_KEY` in `.env` and want the demo to actually charge test-mode
Stripe, build the Stripe-enabled variant instead:

```sh
docker compose -f examples/agentic-commerce-demo/deploy/docker-compose.yml \
  -f examples/agentic-commerce-demo/deploy/docker-compose.stripe.yml up -d --build
```

First boot creates the family workspace (keys, memberships, DID doc) in a
volume. Watch until healthy:

```sh
docker compose -f examples/agentic-commerce-demo/deploy/docker-compose.yml logs -f family
# expect: "trusted merchant dominos" and the console's startup banner
```

## 3. Browser tabs (use `localhost`, never `127.0.0.1`)

| Tab | Purpose |
|-----|---------|
| http://localhost:7300 | **Chat** — type the order here instead of running `claude`. |
| http://localhost:7300/logs | **Live log** — every tool call, policy verdict, and settlement step, streamed. Put this on the projector. |
| http://localhost:7500 ×2 windows | **Sign in, then enroll passkeys**: window A as `child`, window B as `parent` — the role comes from who you sign in as, so there is nothing to choose afterwards. Once per container lifetime; enrollments are in-memory. These windows are also where Touch ID prompts appear. |
| http://localhost:7500/audit | The evidence-chain view — an alternative to `/logs` for a more narrative projector view. |

## 4. Run a flow

In the chat tab (http://localhost:7300):

- **Full loop** (negotiate → signed invoice → passkeys → settle → fulfill):
  *"Get me a cheese slice from Domino's, delivered to 12 Main St — negotiate a
  deal first."* Approve in the child window, then the parent window, with
  Touch ID; watch the chain complete on `/logs` or `/audit`.
- **Deny paths worth showing**: decline an approval; ask the assistant to
  haggle Domino's below 30% off (negotiation succeeds, signature refuses).

The `spend` and legacy `order_pizza` VC-wallet rails still work end to end,
but their wallet browser tabs aren't published in this containerized
flow — see [`README.md`](README.md)'s Notes for running them by hand instead.

## 5. Observability

The `/logs` tab is the primary one now. For the raw container stream (a
superset, including things that happen before the console starts):

```sh
docker compose -f examples/agentic-commerce-demo/deploy/docker-compose.yml logs -f family

# deliveries landing
docker compose -f examples/agentic-commerce-demo/deploy/docker-compose.yml exec pizzaparlor \
  tail -f /data/pizza-orders.log
```

## 6. Reset / teardown

```sh
docker compose -f examples/agentic-commerce-demo/deploy/docker-compose.yml down        # stop (volumes survive)
docker compose -f examples/agentic-commerce-demo/deploy/docker-compose.yml down -v     # full reset: new keys, new trust, re-enroll
```

## Troubleshooting

- **"ports are not available" at `up`** — old host demo processes still
  hold 7300 or 7500; stop those terminals.
- **Chat returns an error on the first message** — almost always a missing
  or invalid `ANTHROPIC_API_KEY`; check step 1.
- **The passkey page asks you to sign in** — that is expected. The username is
  `child` or `parent`; the password is random per workspace and printed at
  startup. Find it with:
  ```sh
  docker compose -f examples/agentic-commerce-demo/deploy/docker-compose.yml \
    logs family | grep 'passkey page sign-in'
  ```
  It is also in the live log at http://localhost:7300/logs. Signing in as
  `parent` is what makes that window the parent — enrollment takes the role
  from the token, not from a control on the page.
- **Passkey prompt errors / credential not found** — you enrolled before a
  container restart (in-memory), or opened `127.0.0.1` instead of
  `localhost`. Re-enroll both roles.
- **The assistant seems stuck retrying a tool call** — it gives up after a
  bounded number of tool rounds and says so in the chat; check `/logs` for
  what it was actually calling.
- **`Failed to connect to 'pizza'` in family logs** — parlor wasn't ready;
  the entrypoint gates on it, so this normally means the parlor crashed:
  check `logs pizzaparlor`.
- **Invoice refused as untrusted merchant** — the boot trust exchange
  didn't run (look for "trusted merchant dominos" in family logs);
  restart the family container.

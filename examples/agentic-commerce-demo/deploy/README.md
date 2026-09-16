# Containerized demo

> Operator checklist: see **[RUNBOOK.md](RUNBOOK.md)** — the short
> bring-it-all-up doc. This file is the longer background.

Two containers on the trust boundary:

- **family** — kid + parent wallets, the WebAuthn approval service, the
  policy proxy, and a browser console that fronts all of it: a chat window
  that drives the proxy through its own MCP endpoint (in place of running
  `claude` in a terminal), and a live log of what happens as a result. One
  launcher process tree; only the console and the passkey approval page are
  published to the host.
- **pizzaparlor** — the merchant's MCP tool server, reached by the family
  proxy over Streamable HTTP across the container network. The container
  boundary stands in for the org boundary (with the limits set out in
  [What the container boundary is and isn't](#what-the-container-boundary-is-and-isnt));
  the merchant build-out (invoice signer behind the parlor's own policy,
  fulfillment commitments, its own agent) grows here. Not published to the
  host at all — everything it does shows up in the family console's log
  instead.

A browser is all you need on the host — no terminal session, no MCP client
to configure.

## Run

The build context is the repo root (`extensible-mcp`):

```sh
cd extensible-mcp
docker compose -f examples/agentic-commerce-demo/deploy/docker-compose.yml up --build
```

First boot creates the family workspace (keys, memberships, DID document)
inside the `family-workspace` volume; it survives restarts, so passkey
enrollments and DIDs stay stable.

Requires `ANTHROPIC_API_KEY` in `.env` (see [RUNBOOK.md](RUNBOOK.md)) — it
now drives the chat console's own agent loop, not just the merchant's
optional LLM clerk.

## Stripe is opt-in at build time, not just at runtime

The default build above never installs the `stripe` SDK at all — the
in-memory mock rail is the only one reachable, regardless of what
environment variables get set. There is no released-image path to any
Stripe account, yours or anyone else's.

To build the variant that *can* reach Stripe (still requires your own
`STRIPE_API_KEY` — this only controls what's installed):

```sh
docker compose -f examples/agentic-commerce-demo/deploy/docker-compose.yml \
  -f examples/agentic-commerce-demo/deploy/docker-compose.stripe.yml up --build
```

Then set `SETTLEMENT=stripe` (and/or `DOWNSTREAM=stripe`) plus your own
`STRIPE_API_KEY=sk_test_...` in `.env`. Setting either on the *default*
build fails with a clear error ("stripe is not installed. Run: uv sync
--extra stripe") instead of a confusing crash or silent fallback.

## Human surfaces (browser tabs)

| Tab | URL | What |
|-----|-----|------|
| **Chat + log** | http://localhost:7300 | talk to the assistant; `/logs` on the same port streams what it and everything else are doing |
| Passkey page | http://localhost:7500 | 2 windows — enroll child + parent once, then Touch ID approvals |
| Audit trail | http://localhost:7500/audit | the projector view: each purchase as a live evidence chain — terms → consent → payment → obligation, every link signed |

Use `localhost` (not `127.0.0.1`) for the passkey page — WebAuthn binds the
credential to the hostname.

## Notes

- The kid/parent wallet services still run (the `spend`/`order_pizza`
  gated actions on the VC-wallet rail depend on them internally), but
  their browser UIs aren't published — this containerized flow drives the
  full negotiate → invoice → passkey → settle → fulfill loop through the
  chat console instead. Run `deploy/family-entrypoint.sh`'s pieces by hand
  (see [`examples/README.md`](../examples/README.md)) if you want the
  wallet tabs directly.
- Passkey enrollments live in the approval service's memory: after a
  container restart, re-enroll in the :7500 tab.
- Orders land in the parlor volume: `docker compose -f … exec pizzaparlor
  cat /data/pizza-orders.log`.
- Stripe rail: needs the Stripe-enabled build (see above) plus `DOWNSTREAM:
  stripe` and `STRIPE_API_KEY` in the family service environment.

## What the container boundary is and isn't

The two containers stand in for two organizations, and the demo's whole
point is that the family's policy trusts the merchant for nothing beyond
its signed invoices. It is worth being exact about how much of that the
compose topology actually enforces, because a reader could reasonably
assume more.

**What it does enforce.** The family's control plane — the policy proxy
(`:7400`) and both wallets (`:7401`/`:7402`) — binds to loopback inside the
family container. Everything that uses those three lives in the same
container, so nothing is lost, and the merchant container cannot reach any
of them: not to drive the proxy as an MCP client, and not to POST a
wallet's `/sign/request` with prompt text and a callback URL of its own
choosing. The merchant also no longer receives the family's
`STRIPE_API_KEY`, which it used to get simply because both containers read
the same `.env`.

**What it doesn't.** The approval service (`:7500`) is published to the
host, because its passkey pages are a human surface — and a port the host
can reach on a single-container service is a port the other container can
reach too. So the merchant container can still reach that service's whole
API, which has no authentication: `/register` mints an admin-signed
enrollment credential for any caller and takes the `role` from the request
body, `/trust-merchant` adds any key to the trusted set, and `/settle`
charges an approved invoice. A compromised merchant could enrol itself as
both child and parent, trust its own key, sign an invoice, approve it, and
settle it, with no human involved.

That is a property of this demo's deployment, not of the enforcement
architecture: the policy still verifies every signature field-by-field, and
it would still refuse evidence that did not verify. What the demo does not
do is authenticate *who is allowed to ask the approval service to vouch for
a key in the first place*.

`/register` is the link that matters. The approval service loads the admin's
private key and will sign an enrollment credential — "this key holds role
*parent*" — for whatever key and whatever role the request names. Its only
production caller is the passkey page's own JavaScript, where the role is a
dropdown. So the sole thing standing between a caller and the household's
trust anchor is *reaching the page*. A WebAuthn assertion then proves the
holder of that key approved these exact terms, which is exactly what it
should prove — but it can never prove the key belongs to a particular human.
That binding is made entirely at enrollment, and the chain is worth no more
than its first link.

The fix is therefore to authenticate enrollment: the requester proves who
they are, and the server derives the role from that identity rather than
believing the request body. Isolating these ports on their own network is
worth doing as well, but it is defence in depth rather than the control to
rely on — trusting an actor by virtue of where it sits is the posture this
project's own [threat model](../../../README.md#threat-model) rejects.
Neither is done here, and a login whose password everyone can guess would be
worse than this paragraph, so the honest position for now is to state it.

## The full loop (what this is actually a demo of)

Pizza is the toy instance of a general non-repudiable-agreement flow —
read it as a corporate/contract pipeline: **invoice = contract draft ·
passkey approvals = signature ceremony bound to the exact draft ·
settlement receipt = consideration · fulfillment commitment = the
counterparty's signed obligation.** Two orgs, two untrusted LLMs, and at
no step does anything bind on an agent's word — only on signatures the
agents cannot forge, over documents they cannot alter.

A complete run, from one prompt ("get me a cheese slice from Domino's,
delivered to 12 Main St"):

1. **Negotiate** — the chat console's assistant talks to Domino's clerk
   (`negotiate`); the clerk may discount, but the merchant's policy caps
   what it can sign.
2. **Invoice** — `request_invoice` returns the merchant-signed terms
   (items, prices, total, delivery address, expiry, single-use nonce).
3. **Approve + settle** — `request_invoice_approval` sends it to the
   family side: the approval service refuses untrusted merchants outright,
   the required humans passkey-sign the **invoice hash** in the `:7500`
   tab, and on full approval the rail (mock by default, or Stripe with the
   Stripe-enabled build plus `SETTLEMENT=stripe` + `STRIPE_API_KEY` — see
   "Stripe is opt-in at build time" above) is charged once and returns a
   settlement-signed **receipt**.
4. **Fulfill** — the chat console's assistant presents the receipt to the
   parlor's `fulfill` tool; the merchant verifies it against the rail it
   trusts and the invoice it actually issued (single-use), schedules the
   delivery, and returns a merchant-signed **fulfillment commitment**.

Trust is exchanged at boot, not by agents: the family entrypoint registers
the parlor's merchant card into its trusted set; the parlor fetches the
settlement authority's card before its first fulfillment.

## The merchant's agent (pizzaparlor)

The parlor exposes an A2A commerce surface alongside `order_pizza`:
`merchant_card` (identity + public key for the buyer's trusted set),
`negotiate` (Domino's sales clerk — an LLM when `ANTHROPIC_API_KEY`
is set in the environment at `compose up`, a deterministic list-price
clerk otherwise), and `request_invoice` (a merchant-**signed** invoice, or
a refusal). The clerk can talk however it likes; the merchant's policy
(menu membership, ≤30% discount floor, quantity and total bounds, quote
TTL) decides what its signature can bind — the org-side mirror of the
family's human approvals. The merchant key persists in the parlor volume,
so the buyer's trust decision survives restarts.

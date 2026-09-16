# Running the demo locally

Two ways to see the enforcement path without Docker: a single self-contained
command, and the full human-in-the-loop version with real wallets. Both are
decided by the same policy bundle — the wallets supply *evidence*, never
authority.

For the containerized version with a browser chat window and a passkey page,
see [`../deploy/`](../deploy/) instead.

## The short version: one command, no wallets

```bash
uv run python examples/boot_demo.py
```

This mints an admin, a kid and a parent in-process, admits a `payments`
downstream to the `family_spend_prod` bundle through a `BundleRouter`, and
drives four calls through a real server lifespan. No network, no keys on
disk, nothing to clean up.

What it shows, in order:

1. **`search_tools`** surfaces the governed `spend` tool with the credential
   requirements the augmenter derives from the bundle's own guidance — the
   obligation arrives as part of the tool definition, not as a side channel.
2. **A call with no credentials** is refused before it reaches the
   downstream: `Policy input could not be assembled: tool call has no field 'requestVC'`.
3. **$5 with the kid's request VC** is allowed — the solo tier — and the
   downstream actually debits: `New balance: $95.00`.
4. **$50 with only the kid's VC** is denied, and the denial explains itself:

   ```
   - Path 1: required: input.requestVC.claims.vc.credentialSubject.requests.amountCents <= 1000.
   - Path 2: provide `authorizationVC`, signed by the parent, which was not supplied.
   ```

   Add the parent's authorization and the same call is allowed.

That last message is the guidance layer rendering `failed_checks` against
`guidance.json`: two alternative paths through the policy, each listing what
it still needs. Nothing in it is hand-written prose about this scenario.

## The full version: real wallets, real approvals

```bash
uv run python examples/setup.py
```

Creates `workspace/` with admin, kid and parent keys (`chmod 0600`), the
admin's DID document, admin-signed membership credentials for both members,
and `vc-config.json`. It prints the exact commands for the next steps; the
shape is:

```bash
# 1. kid's wallet
uv run --package household-identity wallet run \
    --keys-dir workspace/keys --label kid --port 7401 \
    --membership-path workspace/memberships/kid.jwt

# 2. parent's wallet
uv run --package household-identity wallet run \
    --keys-dir workspace/keys --label parent --port 7402 \
    --membership-path workspace/memberships/parent.jwt

# 3. the proxy
uv run python examples/family_proxy_server.py \
    --vc-config workspace/vc-config.json --host 0.0.0.0 --port 7400

# 4. watch orders arrive
tail -f workspace/pizza-orders.log
```

Point an MCP-aware client at `http://127.0.0.1:7400/mcp` and ask it to
order a pizza.

### What gets gated, and by what

`family_proxy_server.py` gates three actions across two bundles:

| Action | Evidence | Bundle |
|---|---|---|
| `spend`, `order_pizza` | kid's request VC, plus the parent's authorization above $10 | `family_spend_prod` |
| `charge_invoice` | a merchant-signed invoice plus both passkey legs | `family_spend_invoice` |

Evidence on both rails is single-use: the proxy wraps each policy filter in `SingleUseEvidenceFilter`, which spends the request VC's `jti` on a call the policy allowed and refuses a second call carrying the same one. Without it the wallet rail would be replayable for the credential's whole validity window — one approval, as many spends as the LLM sent. The invoice rail keys settlement and fulfilment on the invoice nonce as well.

The two wallets above cover `spend` and `order_pizza`. `charge_invoice` also
needs the approval service, which serves the passkey page the human taps:

```bash
APPROVAL_HOST=0.0.0.0 uv run python examples/approval_service.py
```

That page is behind a sign-in: enrolling a passkey mints an admin-signed "this
key holds role *parent*", so it needs an identity to take the role from rather
than a dropdown the caller sets. The service prints the credentials for this
workspace when it starts (`[approval] sign-in credentials: …`) — usernames
`child` and `parent`, passwords random per workspace. Sign in as the role you
want the window to hold, then enrol.

### The pizza walkthrough

The kid tells the assistant to order a pizza. It then:

1. `search_tools("order a pizza")` — `pizza__order_pizza` comes back with
   `vc_request` and `vc_authorization` added to its schema, and a
   description explaining how to obtain them.
2. `request_action_vc(...)` — the proxy POSTs the kid's wallet on :7401,
   which prints the request and waits. The kid approves; the wallet returns
   a signed bundle. Keys never leave the wallet.
3. For anything over $10, `request_authorization_vc(...)` does the same at
   the parent's wallet on :7402, signing an authorization bound to the
   kid's request by `jti` and a SHA-256 hash of its compact JWS.
4. `call_tool("pizza__order_pizza", {...})` with both bundles attached. The
   bundle's policy then checks, among other things, that what the kid
   actually signed matches the call being made — the amount and the store,
   field by field. Mismatched evidence is refused however valid its
   signatures are.
5. On success the credential arguments are stripped and the bare order is
   forwarded downstream, which appends to `pizza-orders.log`.

Decline at step 2 or 3 and the call never reaches the pizza shop.

Both wallets also support a browser approval page instead of the terminal
prompt — add `--approve web` and open `/ui` on the wallet's port. That is
what the containerized demo uses.

## Cleanup

`rm -rf workspace/`. All state is in there.

# extensible-mcp-vc

The package behind the **Order Pizza** demo, in `examples/agentic-commerce-demo/`. Signed-evidence enforcement for [extensible-mcp](../../README.md): a gated tool is not invoked unless the call carries evidence that the action was actually requested and authorized — a wallet-signed credential, a passkey assertion, a merchant's signed invoice. The LLM's word that "the user said yes" is not enough.

## Why

extensible-mcp's threat model rests on a single premise: an LLM that can be prompt-injected into deleting a file can also be prompt-injected into supplying a `confirmation: "CONFIRM_DELETE"` argument. Anything the LLM produces is potentially adversary-controlled. Authorization for sensitive actions has to live in a channel the LLM cannot influence.

This package supplies that channel by requiring W3C Verifiable Credentials at call time. Each gated call carries two JWT-VCs: one signed by the originator (the principal asking for the action), one signed by the approver (the principal authorizing it), bound to each other so the LLM cannot swap an authorization for one request onto a different request. Both signers must be current members of a trust network rooted at a `did:web` admin.

The sibling package [`household-identity`](../identity) provides the wallet service that holds keys and prompts the human for approval, and the DID server that publishes the admin's DID document and issues membership credentials. The two packages together implement the demo's wallet rail; healthcare and other deployments reuse the same primitives with a different trust anchor.

## Read this first: two enforcement paths, three rails

This package accreted in layers, and **all of them still ship and still work** — which makes it easy to read one layer's documentation as though it described the whole thing. It doesn't. Two things changed as the package grew:

**Where the decision lives.** Originally `VCCallFilter` verified the credential chain in hand-written Python. Now the same class of decision is expressed as a **policy bundle** — a schema, a fetch plan, guidance, and rules in Rego-compiled-to-WASM or CEL — evaluated by an engine, with a thin *wire adapter* mapping on-the-wire credential names onto the policy's input contract. The Python didn't get smarter; it got out of the way of something auditable.

**What counts as evidence.** It started as wallet-signed JWT-VCs. It now also includes WebAuthn passkey assertions and merchant-signed invoices carrying their own Ed25519 signatures over exact canonical bytes.

The two entry points under [`examples/`](examples/) mark the divide:

| | `proxy_server.py` | `family_proxy_server.py` |
|---|---|---|
| Wiring | `extend_server()` | `create_server(bundle_router=…)` |
| Authority | `VCCallFilter` (hand-coded) | `BundleRouter` over policy bundles |
| Gated | `payments__spend`, `pizza__order_pizza` | `spend`, `order_pizza`, `charge_invoice` |
| Walkthrough | [`examples/README.md`](examples/README.md) | [`deploy/README.md`](deploy/README.md) |

`family_proxy_server.py` runs three rails **at once**, one per gated tool, each with different evidence and a different wire adapter over the same bundle machinery:

- **`spend`** → passkey assertion, `family_spend_webauthn` bundle
- **`order_pizza`** → the two-VC wallet chain, `family_spend_prod` bundle — the *same evidence* as the original path, now decided by a bundle rather than by Python
- **`charge_invoice`** → merchant-signed invoice plus both passkey legs, `family_spend_invoice` bundle, externally authored and certified

That they coexist is the point: the pipeline composes enforcement mechanisms rather than replacing one with the next.

**So: the two sections immediately below describe the original two-VC path**, which remains accurate for `proxy_server.py` and for the `extend_server()` API. For the bundle format itself see the [root README's Policy bundles section](../../README.md#policy-bundles); for the full commerce flow see [`deploy/`](deploy/).

## The two-VC chain

Every gated call requires:

1. **Request VC** — signed by the originator's `did:key`, naming the action and its parameters (e.g. *"I, did:key:Bobby, request spend $15 at the pizza shop"*). Travels with a `FamilyMembership` JWT issued by the admin that binds Bobby's `did:key` to the trust network with a role and expiry.
2. **Authorization VC** — signed by the approver's `did:key`, bound to the request by `jti` AND the SHA-256 hash of the request VC's compact JWS. Travels with the approver's own membership JWT.

The filter verifies, in order:

- Both VC signatures against the issuer `did:key`s (no network lookup; `did:key` is computational).
- The authorization is bound to *this specific* request (jti match plus content hash).
- Both membership VCs verify against the admin's `did:web` key (resolved via HTTPS, cached with TTL).
- Each membership's `sub` matches the VC's signer.
- All three credentials are within their `nbf`/`exp` window.

On success, `vc_request` and `vc_authorization` are stripped from the arguments and the bare tool call is forwarded to the downstream MCP server. On failure the call is refused with a structured reason.

## What the package contributes

Three pieces, all wired in through `extensible-mcp`'s public extension points:

- `VCSchemaAugmenter` — a `ToolFilter` that, for every gated tool returned by `search_tools`, adds `vc_request` and `vc_authorization` to the input schema with an "Authorization required" addendum to the description. The LLM sees the obligation as part of the tool definition; there is no side channel.
- `VCCallFilter` — a `CallFilter` that performs the verification chain above for gated tools and passes through for non-gated tools.
- Two tools the LLM uses to obtain VCs from wallets: `request_action_vc` and `request_authorization_vc`. The proxy POSTs to the configured wallet endpoints, the wallet prompts the human for approval, and returns the signed bundle. Keys never leave the wallet; VCs never leave the proxy's control path. They're supplied to `create_server` as `local_tools` and reached through `call_tool` like any other tool — *not* registered directly on the FastMCP server, which would put them outside the filter pipeline entirely (see the root README's [Adding your own tools](../../README.md#adding-your-own-tools)).

Gating is configured as a list of tool names plus `fnmatch` patterns. Anything not gated passes through untouched — richer policy belongs to a Rego call filter or a policy bundle, either of which composes with this one.

## Usage

```python
from extensible_mcp.config import load_config
from extensible_mcp_vc import VCConfig, extend_server

config = load_config("config.json")
vc_config = VCConfig(
    gated_tools=["payments__spend"],
    trusted_admin_dids=["did:web:family.example.com"],
    originator_wallet_url="http://localhost:7401",
    approver_wallet_url="http://localhost:7402",
)
server = extend_server(config, vc_config)
server.run()
```

`extend_server` accepts the same `extra_*_filters` kwargs as `extensible_mcp.create_server`; the VC augmenter and filter are prepended to whatever you pass.

For air-gapped tests or fixed deployments, `VCConfig` exposes `preresolved_did_documents` to skip the HTTPS lookup for known DIDs.

## Example

[`examples/`](examples/) contains a runnable family-spend demo: two wallets (kid, parent), an admin DID server, a mock payments backend, and a proxy that gates `payments__spend`. `examples/setup.py` initializes the workspace; `examples/README.md` walks through the kid-asks → parent-approves flow end to end.

The larger negotiate → invoice → passkey → settle → fulfill commerce demo runs containerized (see [`deploy/`](deploy/)): a chat window drives the proxy in place of a terminal `claude` session, a live log replaces grepping container output by hand, and only those two surfaces plus the passkey approval page are exposed — everything else stays internal to the container network.

## Status

`0.0.1` — feature complete. 172 tests pass (1 skipped without a workspace admin key). Not yet on PyPI; resolved as an editable workspace member of the parent repo (see [`../../pyproject.toml`](../../pyproject.toml)).

Deferred to later versions: StatusList revocation (currently relying on credential expiry), JSON-LD VCs (JWT-VC only for now). A web approval UI now ships (`wallet run --approve web`, and the WebAuthn passkey page for the commerce demo) alongside the original stdin prompt.

## License

Apache License 2.0 — see [LICENSE](../../LICENSE).

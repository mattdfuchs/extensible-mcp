# extensible-mcp-vc

The package behind the **Order Pizza** demo, in `examples/agentic-commerce-demo/`. Signed-evidence enforcement for [extensible-mcp](../../README.md): a gated tool is not invoked unless the call carries evidence that the action was actually requested and authorized — a wallet-signed credential, a passkey assertion, a merchant's signed invoice. The LLM's word that "the user said yes" is not enough.

## Why

extensible-mcp's threat model rests on a single premise: an LLM that can be prompt-injected into deleting a file can also be prompt-injected into supplying a `confirmation: "CONFIRM_DELETE"` argument. Anything the LLM produces is potentially adversary-controlled. Authorization for sensitive actions has to live in a channel the LLM cannot influence.

This package supplies that channel by requiring W3C Verifiable Credentials at call time. Each gated call carries two JWT-VCs: one signed by the originator (the principal asking for the action), one signed by the approver (the principal authorizing it), bound to each other so the LLM cannot swap an authorization for one request onto a different request. Both signers must be current members of a trust network rooted at a `did:web` admin.

The sibling package [`household-identity`](../identity) provides the wallet service that holds keys and prompts the human for approval, and a DID server that publishes the admin's DID document and issues membership credentials. The demo's own walkthrough never starts that server: `setup.py` issues the memberships directly and hands the proxy the admin's DID document through `preresolved_did_documents`, so nothing has to be resolved over HTTPS on a laptop. A deployment where the admin is genuinely remote runs it. The two packages together implement the demo's wallet rail; healthcare and other deployments reuse the same primitives with a different trust anchor.

## One enforcement path, two rails

Every gated call is decided by a **policy bundle** — a manifest, a fetch plan, guidance, and rules in Rego-compiled-to-WASM or CEL — evaluated by `extensible-mcp`'s engine. This package doesn't decide anything itself. It supplies the evidence a bundle decides over, plus a thin *wire adapter* per rail that maps the on-the-wire argument names onto the policy's input contract.

`family_proxy_server.py` runs two rails at once, all over the same machinery:

| Action | Evidence | Bundle |
|---|---|---|
| `spend`, `order_pizza` | kid's request VC, plus the parent's authorization above $10 | `family_spend_prod` |
| `charge_invoice` | a merchant-signed invoice plus both passkey legs | `family_spend_invoice` |

That they coexist is the point: one pipeline, one decision mechanism, two quite different kinds of evidence — a credential a human signed in a wallet, and a merchant's own signature over terms it is bound to honour.

Two entry points under [`examples/`](examples/): `boot_demo.py` mints its keys in-process and drives a scripted run in one command, and `family_proxy_server.py` is the real thing with wallets and browser approval. Both are covered in [`examples/README.md`](examples/README.md); for the containerized version see [`deploy/`](deploy/), and for the bundle format itself the [root README's Policy bundles section](../../README.md#policy-bundles).

## The two-VC chain

Every gated call requires:

1. **Request VC** — signed by the originator's `did:key`, naming the action and its parameters (e.g. *"I, did:key:Bobby, request spend $15 at the pizza shop"*). Travels with a `FamilyMembership` JWT issued by the admin that binds Bobby's `did:key` to the trust network with a role and expiry.
2. **Authorization VC** — signed by the approver's `did:key`, bound to the request by `jti` AND the SHA-256 hash of the request VC's compact JWS. Travels with the approver's own membership JWT.

The policy governing the tool verifies, among its other conditions:

- Both VC signatures against the issuer `did:key`s (no network lookup; `did:key` is computational).
- The authorization is bound to *this specific* request (jti match plus content hash).
- Both membership VCs against the admin's `did:web` key, resolved via HTTPS by the proxy and supplied as policy input — the fetch plan's `wallet` source, since HTTPS I/O cannot happen inside a WASM policy.
- Each membership's `sub` matches its VC's signer, and carries the role the tier requires.
- All three credentials within their `nbf`/`exp` window, against a clock the policy is handed rather than reads.
- **That what was signed matches the call being made** — the amount and the merchant, field by field. Evidence that authorizes a different action than the one requested is refused however valid its signatures are.

On success the credential arguments are stripped and the bare tool call is forwarded downstream. On failure the call is refused with the guidance layer's rendered explanation of which conditions failed and what is still missing.

## What the package contributes

Evidence and adaptation, wired in through `extensible-mcp`'s public extension points. The decision belongs to the bundle:

- **Tools the LLM calls to obtain evidence** — `request_action_vc` and `request_authorization_vc` for the wallet rail, `request_invoice_approval` for passkey approval of a merchant-signed invoice, `record_fulfillment` to file the merchant's commitment. The proxy POSTs the configured wallet or approval endpoint, a human approves there, and the signed result comes back. Keys never leave the wallet. These are supplied to `create_server` as `local_tools` and reached through `call_tool` like any other tool — *not* registered directly on the FastMCP server, which would put them outside the filter pipeline entirely (see the root README's [Adding your own tools](../../README.md#adding-your-own-tools)).
- **Wire adapters** — one per rail, mapping a tool's own argument vocabulary onto the policy's input contract. `order_pizza` speaks `(store, total)`; the policy binds `(merchant, amountCents)`. The rename happens for the policy's view only; the downstream still receives its own names.
- **The signed artifacts themselves** — the canonical invoice form a merchant signs, the WebAuthn challenge construction, and the settlement and fulfillment legs.

## Usage

Enforcement is wired with `extensible-mcp`'s own `create_server`, giving it a
`bundle_router` that maps each downstream server to the bundle governing it:

```python
from extensible_mcp import BundleRouter, LayeredBundleSelector
from extensible_mcp.server import create_server

router = BundleRouter(selector, filter_factory)
server = create_server(config, bundle_router=router, local_tools=evidence_tools)
```

[`examples/boot_demo.py`](examples/boot_demo.py) is the smallest complete version of that — under 200 lines, no wallets, runnable in one command. [`examples/family_proxy_server.py`](examples/family_proxy_server.py) is the full one, with both rails and real wallets.

For air-gapped tests or fixed deployments, `VCConfig` exposes `preresolved_did_documents` to skip the HTTPS lookup for known DIDs.

## Example

[`examples/README.md`](examples/README.md) covers both local runs: the one-command scripted version, and the full one with two wallets, browser approval, and a pizza log you can `tail -f`.

The larger negotiate → invoice → passkey → settle → fulfill commerce demo runs containerized (see [`deploy/`](deploy/)): a chat window drives the proxy in place of a terminal `claude` session, a live log replaces grepping container output by hand, and only those two surfaces plus the passkey approval page are exposed — everything else stays internal to the container network.

## Status

`0.0.1` — feature complete. 114 tests pass (1 skipped without a workspace admin key). Not yet on PyPI; resolved as an editable workspace member of the parent repo (see [`../../pyproject.toml`](../../pyproject.toml)).

Deferred to later versions: StatusList revocation (currently relying on credential expiry), JSON-LD VCs (JWT-VC only for now). A web approval UI now ships (`wallet run --approve web`, and the WebAuthn passkey page for the commerce demo) alongside the original stdin prompt.

## License

Apache License 2.0 — see [LICENSE](../../LICENSE).

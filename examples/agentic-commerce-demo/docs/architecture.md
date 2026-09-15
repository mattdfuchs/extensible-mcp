# Architecture

Two enforcement paths sit on the same model — *N cheap authenticated approvals →
a typed policy → one heavy execution act* — wired at different points:

1. **MCP call gate** — the LLM reaches tools only through the retrieval proxy,
   and a `spend` call is authorized by a supplied policy bundle against wallet
   VCs before it ever reaches the payment rail.
2. **Commerce / human-approval path** (stages 1–3) — a merchant-signed invoice
   is negotiated over A2A, verified against a trusted-merchant set, bound to
   child + parent WebAuthn approvals, settled on the rail for exactly its terms,
   and fulfilled by the merchant against a signed payment receipt.

Legend for both diagrams: **solid** = implemented runtime flow · **dashed** =
trust anchor / build-time provenance · **dotted** = designed but not yet wired.

## System components (MCP enforcement path)

<details><summary>Diagram source (Mermaid)</summary>

```mermaid
flowchart TB
    agent(["Family LLM agent"])

    subgraph provenance["Policy provenance (build time)"]
        direction LR
        spec["Policy spec<br/>family_spend"] -->|"authoring toolchain"| rego["Rego or CEL"]
        rego -->|"opa build / checks.cel.json"| wasm[("policy bundle<br/>manifest · fetchplan · guidance")]
    end

    subgraph identity["Identity — VC issuance"]
        direction LR
        admin["did:web admin"] -->|"issues membership VCs"| wallets["Wallets<br/>child · parent<br/>did:key Ed25519"]
    end

    subgraph proxy["extensible-mcp — retrieval proxy (FastMCP)"]
        meta["Meta-tools<br/>search_tools · call_tool · load_mcp_server"]
        vec[("Vector index<br/>FastEmbed MiniLM")]
        disc["DiscoveredToolsFilter<br/>structural: only surfaced tools are callable"]
        vcf["VCPolicyFilter + WalletBundleAdapter<br/>authorization gate"]
        cm["Client manager"]
        meta -->|"embed + cosine"| vec
        meta -->|"call_tool"| disc --> vcf --> cm
    end

    subgraph rails["Downstream execution rails — MCP servers"]
        stripe["stripe_spend_server<br/>test-mode PaymentIntent"]
        demo["demo_spend_server<br/>mock balance"]
    end

    agent -->|"only the 3 meta-tools"| meta
    wallets -->|"request VC + authorization VC"| vcf
    wasm -.->|"policy authority"| vcf
    admin -.->|"trusted-admin set"| vcf
    cm -->|"spend(amount, merchant)"| stripe
    cm --> demo
```

</details>

The LLM never sees the whole tool catalogue or the payment credential: it gets
three meta-tools, discovers tools by vector search, and every `call_tool` passes
`DiscoveredToolsFilter` (can't call what it never surfaced) then `VCPolicyFilter`
(the policy bundle, evaluated over the child's request VC and the parent's
authorization VC, anchored to the trusted-admin set). Only then does the client
manager proxy `spend` to the rail.

## Commerce path — stages 1–3 (negotiate → approve → pay → fulfill)

![Commerce sequence](img/commerce-seq.svg)

<details><summary>Diagram source (Mermaid)</summary>

```mermaid
sequenceDiagram
    autonumber
    actor H as Human
    participant B as "Family agent<br/>(buyer · negotiate.py)"
    participant M as "Merchant agent<br/>(Ed25519 signer)"
    participant A as "Approval service<br/>(WebAuthn + trusted-merchant set)"
    actor C as Child
    actor P as Parent
    participant R as Stripe rail

    H->>B: "order a large pepperoni"
    B->>M: GET /merchant-card, /menu  (A2A discovery)
    M-->>B: card (public key) + menu
    Note over B,A: trust decision (human / config), out of band
    B->>A: POST /trust-merchant {merchantId, publicKey}
    B->>M: POST /quote {items}
    M-->>B: signed invoice — priced by the merchant
    B->>B: verify invoice vs trusted set (advisory)
    B->>A: POST /request-invoice {invoice, signature}
    A->>A: verify signature + trusted + not expired (authoritative)
    A->>A: required roles from amount, challenge = hash(invoice)
    C->>A: POST /approve — biometric signs the invoice hash
    P->>A: POST /approve — biometric signs the invoice hash
    A->>R: charge the invoice's terms — nonce as idempotency key
    R-->>A: payment reference (succeeded)
    A->>A: sign payment receipt (settlement key)
    A-->>B: status: settled + signed receipt
    B->>M: POST /fulfill {receipt}
    M->>M: verify receipt vs trusted rail key + the order it issued
    M-->>B: fulfilled — ships once (nonce is single-use)
```

</details>

The A2A channel is **untrusted**: a manipulated buyer agent can garble or drop
the negotiation, but it cannot forge terms — the merchant's signature over a
concrete invoice is the only thing that carries weight, and the approval service
re-verifies it authoritatively against the trusted-merchant set before any human
is asked. Each biometric binds to `hash(invoice)`, so an approval for one invoice
can never authorize another.

The same discipline carries through settlement and fulfilment: the rail is
charged for exactly the invoice's terms with the invoice `nonce` as the
idempotency key (no double-charge on retry), and the merchant ships only against
a receipt signed by the rail it trusts, matched to the order it issued, exactly
once. No hop — buyer agent included — is believed on its word; every one carries
verifiable signed evidence.

## How the two paths relate

Both realize the same decomposition — several cheap, non-repudiable approvals
gate one expensive execution act — but at different seams, and they are not yet
unified:

- The **VC path** proves *who authorized* via wallet-issued VCs checked by the
  supplied policy bundle inside the MCP call gate.
- The **WebAuthn path** proves *a human physically approved this exact object*
  and binds the merchant's committed terms.

<details><summary>Diagram source (Mermaid)</summary>

```mermaid
flowchart LR
    webauthn["WebAuthn approvals<br/>(bound to invoice hash)"]
    bundle["policy bundle<br/>family_spend_webauthn"]
    gate["MCP call gate<br/>VCPolicyFilter"]
    webauthn -.->|"evidence — deferred, awaits bundle"| bundle -.-> gate
```

</details>

Convergence — having the `family_spend_webauthn` policy bundle consume
WebAuthn evidence so a single policy governs both the VC chain and the human
biometric at the MCP call gate — is designed but deferred.
It is now the only deferred seam: the commerce path runs end to end through
settlement and fulfilment (stage 3).

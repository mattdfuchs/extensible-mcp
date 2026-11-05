# Fixture provenance — cedar_family_spend_prod (Cedar, production VC verification)

The Cedar twin of `family_spend_prod` (Rego) and `cel_family_spend_prod` (CEL): the production multi-key policy — per-signer `did:key`, a `did:web` admin membership chain, nested W3C-VC claims, a solo tier at or under $10 and a full-chain tier up to $200 with a co-signed authorization bound by `jti` and a SHA-256 of the request's JWS — decided by a third engine, with the token/evidence seam (`account_bound`).

**Supplied by an external policy-authoring toolchain**, the same one behind
the adopted `family_spend_*` bundles, emitted from its own `family_spend_prod` core in
the **permit-decides** shape (one `@tier` permit per tier, probe-guarded
`@id` forbids, `expected_ids.json` declaring the shape), at upstream commit
`364c4da`. Generator-internal names were anonymized for this public release —
the header's first line, the `goal:` line, `expected_ids.json`'s `goal`,
and `contract.json`'s `goal`, `hypotheses` heads and owner labels; nothing
executable changed. Digest of the **unedited** `policy.cedar` as the
supplier published it:

```
sha256  c2e648aca8f917a5da6f407ac0bea35267b2f19f431a216606894f26746f1656
bytes   37,847
```

| file | origin |
|---|---|
| `policy.cedar` | supplied: 2 `@tier` permits, 34 `@id` forbids, 2 `@assembly` forbids |
| `expected_ids.json` | supplied: the 34 ids and 2 tiers, `"shape": "permit-decides"` |
| `contract.json` | supplied: 6 derivation obligations (the host's half), and the certificate's eight hypotheses with an owner each — `exSound` is the supplier's and marked not yet discharged per bundle |
| `manifest.json` | supplied: the Rego twin's manifest plus 6 derived-field properties, never `required` |
| `fetchplan.json` | supplied: the Rego twin's plan **verbatim**, plus 6 `derive` entries and a `primitives` block |
| `guidance.json` | supplied, byte-identical to the Rego and CEL twins'; `guidance_digest.value = "c776a057d78a4999"` |

`tests/test_fixture_corpus.py` holds the twin relation: the Rego bundle's manifest and plan, verbatim, plus exactly what Cedar forces. `tests/test_vc_policy.py` runs every production scenario on this bundle beside its two twins, including the seam's rows, through `VCPolicyFilter`.

Crypto never runs inside a Cedar policy: each cryptographic leaf is a
`derive` entry in the fetch plan — a witness set the rule tests a relation
over (`.contains`) — and `contract.json` states the obligation per derived
field: exactly the candidates for which the primitive holds, and no other
value. See `../cedar_family_spend_forbid_only/PROVENANCE.md` for why
over-inclusion is the direction that matters and how `DeriveResolver`
collects witnesses by identity. The loader refuses any `in` token and
builds the PARC head per call; this bundle uses the unconstrained scope
and reads everything from `context`, as every supplied Cedar bundle does.

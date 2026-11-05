# Fixture provenance — cedar_family_spend_webauthn (Cedar, production, passkey approval)

The Cedar twin of `family_spend_webauthn` (Rego) and `cel_family_spend_webauthn` (CEL): the production policy whose full-chain tier is authorized by a WebAuthn assertion over the canonical action, verified against an admin-signed enrollment, with the token/evidence seam (`account_bound`).

**Supplied by an external policy-authoring toolchain**, the same one behind
the adopted `family_spend_*` bundles, emitted from its own `family_spend_webauthn` core in
the **permit-decides** shape (one `@tier` permit per tier, probe-guarded
`@id` forbids, `expected_ids.json` declaring the shape), at upstream commit
`364c4da`. Generator-internal names were anonymized for this public release —
the header's first line, the `goal:` line, `expected_ids.json`'s `goal`,
and `contract.json`'s `goal`, `hypotheses` heads and owner labels; nothing
executable changed. Digest of the **unedited** `policy.cedar` as the
supplier published it:

```
sha256  837d9e9aa3520ee7f7b22040d4a702b1f9ab730b1cf59ef3a1440d22555be9bb
bytes   36,354
```

| file | origin |
|---|---|
| `policy.cedar` | supplied: 2 `@tier` permits, 32 `@id` forbids, 2 `@assembly` forbids |
| `expected_ids.json` | supplied: the 32 ids and 2 tiers, `"shape": "permit-decides"` |
| `contract.json` | supplied: 8 derivation obligations (the host's half), and the certificate's eight hypotheses with an owner each — `exSound` is the supplier's and marked not yet discharged per bundle |
| `manifest.json` | supplied: the Rego twin's manifest plus 8 derived-field properties, never `required` |
| `fetchplan.json` | supplied: the Rego twin's plan **verbatim**, plus 8 `derive` entries and a `primitives` block |
| `guidance.json` | supplied, byte-identical to the Rego and CEL twins'; `guidance_digest.value = "3d5e03e7a83b5b65"` |

`tests/test_fixture_corpus.py` holds the twin relation. `tests/test_webauthn_policy.py` runs every scenario on this bundle beside its two twins, including the seam's rows; the challenge canonicalization is derived by the plan (`concat`, `format_int`, `sha256`) and the assertion by `verify_webauthn`, both registered primitives, so the bundle loads only with a relying-party id supplied.

Crypto never runs inside a Cedar policy: each cryptographic leaf is a
`derive` entry in the fetch plan — a witness set the rule tests a relation
over (`.contains`) — and `contract.json` states the obligation per derived
field: exactly the candidates for which the primitive holds, and no other
value. See `../cedar_family_spend_forbid_only/PROVENANCE.md` for why
over-inclusion is the direction that matters and how `DeriveResolver`
collects witnesses by identity. The loader refuses any `in` token and
builds the PARC head per call; this bundle uses the unconstrained scope
and reads everything from `context`, as every supplied Cedar bundle does.

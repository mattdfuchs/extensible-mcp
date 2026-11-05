# Fixture provenance — cedar_family_spend_invoice (Cedar, production, invoice settlement)

The Cedar twin of `family_spend_invoice` (Rego) and `cel_family_spend_invoice` (CEL): the merchant-signed invoice policy, a solo tier approved by the child's passkey and a dual tier adding the parent's, with the token/evidence seam on the child's enrollment (`child_enrollment.account_bound`, the `accounts` disjunct alone, since an enrollment's subject is a credential id and not an account).

**Supplied by an external policy-authoring toolchain**, the same one behind
the adopted `family_spend_*` bundles, emitted from its own `family_spend_invoice` core in
the **permit-decides** shape (one `@tier` permit per tier, probe-guarded
`@id` forbids, `expected_ids.json` declaring the shape), at upstream commit
`364c4da`. Generator-internal names were anonymized for this public release —
the header's first line, the `goal:` line, `expected_ids.json`'s `goal`,
and `contract.json`'s `goal`, `hypotheses` heads and owner labels; nothing
executable changed. Digest of the **unedited** `policy.cedar` as the
supplier published it:

```
sha256  8bbd64165f8891daf6accae3e1f16c564d91c03c31f25979031e6704ab0ca1be
bytes   32,940
```

| file | origin |
|---|---|
| `policy.cedar` | supplied: 2 `@tier` permits, 34 `@id` forbids, 2 `@assembly` forbids |
| `expected_ids.json` | supplied: the 34 ids and 2 tiers, `"shape": "permit-decides"` |
| `contract.json` | supplied: 9 derivation obligations (the host's half), and the certificate's eight hypotheses with an owner each — `exSound` is the supplier's and marked not yet discharged per bundle |
| `manifest.json` | supplied: the Rego twin's manifest plus 9 derived-field properties, never `required` |
| `fetchplan.json` | supplied: the Rego twin's plan **verbatim**, plus 9 `derive` entries and a `primitives` block |
| `guidance.json` | supplied, byte-identical to the Rego and CEL twins'; `guidance_digest.value = "d511c75035a69d5a"` |

`tests/test_fixture_corpus.py` holds the twin relation; `tests/test_invoice_policy.py` is where the invoice scenarios run.

Crypto never runs inside a Cedar policy: each cryptographic leaf is a
`derive` entry in the fetch plan — a witness set the rule tests a relation
over (`.contains`) — and `contract.json` states the obligation per derived
field: exactly the candidates for which the primitive holds, and no other
value. See `../cedar_family_spend_forbid_only/PROVENANCE.md` for why
over-inclusion is the direction that matters and how `DeriveResolver`
collects witnesses by identity. The loader refuses any `in` token and
builds the PARC head per call; this bundle uses the unconstrained scope
and reads everything from `context`, as every supplied Cedar bundle does.

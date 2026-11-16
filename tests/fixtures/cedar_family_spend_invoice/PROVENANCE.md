# Fixture provenance — cedar_family_spend_invoice (Cedar, production, invoice settlement)

The Cedar twin of `family_spend_invoice` (Rego) and `cel_family_spend_invoice` (CEL): the merchant-signed invoice policy, a solo tier approved by the child's passkey and a dual tier adding the parent's, with the token/evidence seam on the child's enrollment (`child_enrollment.account_bound`, the `accounts` disjunct alone, since an enrollment's subject is a credential id and not an account).

**Supplied by an external policy-authoring toolchain**, the same one behind
the adopted `family_spend_*` bundles, emitted from its own `family_spend_invoice` core in
the **permit-decides** shape (one `@tier` permit per tier, probe-guarded
`@id` forbids, `expected_ids.json` declaring the shape), at upstream commit
`64c41c5` (first adopted at `364c4da`, re-pinned below). Generator-internal names were anonymized for this public release —
the header's first line, the `goal:` line, `expected_ids.json`'s `goal`,
and `contract.json`'s `goal`, `hypotheses` heads and owner labels; nothing
executable changed. Digest of the **unedited** `policy.cedar` as the
supplier published it:

```
sha256  9ac531f8b2a65dd6d86442163d6a412aa96d6768f2a95ceaa55efa4ef86a0246
bytes   30,677
```

**Re-pinned 2026-11-16 to upstream `64c41c5`.** Two upstream changes to the
emitted text, both proved decision-preserving by the supplier and asked for
as one re-pin each: the `untruthy` image moved into Cedar's validator's
fragment (each arm of a disjunction re-states the `has` an earlier arm
refuted, and a field the manifest types non-boolean gets no `== false` arm;
integration doc §13.65), and a tier's deciding permit prints each `has` test
once, at its first occurrence, instead of once per leaf (spec §37). The
`contract.json` gains the `typed` hypothesis — a value the host supplies at
a non-boolean field is never the boolean `false` — which the proxy discharges
by validating the assembled input against `manifest.json` before Cedar sees
it. `schema.json` is new: the manifest in Cedar's schema notation, derived
by the supplier and never authored beside it, which the loader now validates
the policy set against at load as a hard gate. Ids, manifest, plan and
guidance are byte-identical to the previous pin.

| file | origin |
|---|---|
| `policy.cedar` | supplied: 2 `@tier` permits, 34 `@id` forbids, 2 `@assembly` forbids |
| `expected_ids.json` | supplied: the 34 ids and 2 tiers, `"shape": "permit-decides"` |
| `contract.json` | supplied: 9 derivation obligations (the host's half), and the certificate's eight hypotheses with an owner each — `exSound` is the supplier's and marked not yet discharged per bundle |
| `schema.json` | supplied: the manifest in Cedar's JSON schema notation, derived from the manifest, partitioned by the plan's `entities` block (none here: every field is `context`); the loader validates `policy.cedar` against it at load |
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
collects witnesses by identity. The loader builds the PARC head per call and forms the entity store from
the plan's `entities` block; this bundle ships none, so its store is the
empty one, it uses the unconstrained scope, and it reads everything from
`context`. With `schema.json` beside the policy an `in` would be checked
against the schema's relations rather than refused outright; this bundle
tests none.

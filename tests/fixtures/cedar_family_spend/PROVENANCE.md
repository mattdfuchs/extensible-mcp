# Fixture provenance — cedar_family_spend (Cedar, teaching scenario, permit-decides)

The teaching policy on the third engine, in the shape a hand author would
write and the only one the toolchain now emits: the kid's-request /
parent's-authorization scenario of `family_spend` (Rego) and
`cel_family_spend` (CEL), plus the token/evidence seam the hand-written
`cel_family_spend_bound` carries — 31 named check ids in two tiers.

**Supplied by an external policy-authoring toolchain**, emitted from its own
`family_spend` core in the permit-decides shape at upstream commit `64c41c5` (first adopted at
`364c4da`, re-pinned below).
It replaces, as of 2026-11-05, two directories: the supplier's forbid-only
emission that was `cedar_family_spend` (now frozen as
`../cedar_family_spend_forbid_only`), and `cedar_family_spend_compact`, the
supplier's 2026-10-27 permit-decides emission of the same 29-check policy
before the seam, which this one supersedes. Generator-internal names were
anonymized as for every supplied bundle; nothing executable changed. Digest
of the **unedited** `policy.cedar` as published:

```
sha256  498c005a5cdd996917a59d0c41c1e0a0ee1f898dc19b67f8d4af053fb4b25a42
bytes   24,034
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
| `policy.cedar` | supplied: 2 `@tier` permits, 31 `@id` forbids, 2 `@assembly` forbids; no `@sentence` |
| `expected_ids.json` | supplied: the 31 ids and 2 tiers, `"shape": "permit-decides"` |
| `contract.json` | supplied: 5 derivation obligations and the certificate's eight hypotheses with an owner each |
| `schema.json` | supplied: the manifest in Cedar's JSON schema notation, derived from the manifest, partitioned by the plan's `entities` block (none here: every field is `context`); the loader validates `policy.cedar` against it at load |
| `manifest.json` | supplied: the supplier's teaching manifest with the seam (`callerIdp`, `callerAccount`, `Account` closed) plus 5 derived-field properties |
| `fetchplan.json` | supplied: the supplier's teaching plan, with the two `caller` entries, plus 5 `derive` entries and a `primitives` block |
| `guidance.json` | **this repo's own**, byte-identical to `cel_family_spend_bound/guidance.json` |

`guidance.json` is ours for the reason the frozen twin's note gives: the
teaching family carries hand-authored sentences, and the four teaching
siblings must render one sentence per id. The bound CEL bundle's file is
the one with all 31, and `tests/test_fixture_corpus.py` pins the byte
identity and that `expected_ids.json` names its ids, tier by tier.

The supplier's manifest and plan are *not* byte-related to the bound CEL
bundle's, and deliberately so: the supplier orders the two `caller` entries
before the memberships, carries no `description` on them, and leaves
`authorizationVC` and `approverMembership` optional — the reading where a
tier the call never needed drops out quietly — where the hand-written
bundle requires them. The policy was proven safe against *its* manifest,
so substituting the other would void that; the differential in
`tests/test_three_engine_differential.py` is what holds the four to one
verdict and one set of ids on every scenario.

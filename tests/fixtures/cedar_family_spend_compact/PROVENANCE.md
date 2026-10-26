# Fixture provenance — cedar_family_spend_compact (Cedar, re-shaped by this repository)

The fourth twin of `family_spend`: the same 29 conditions and two tiers as
`../cedar_family_spend`, in the other policy-set shape the loader accepts.
**Derived mechanically by this repository**, not supplied, from the adopted
`../cedar_family_spend/policy.cedar` (whose rules were supplied by an
external policy-authoring toolchain): each leaf forbid's own condition was
cut at its trailing `&& !(` — the negation of the other tier that the
forbid-only shape must inline into every leaf — and each tier's conjunction
was taken once from the other tier's negation and placed in a `@tier`
permit. Guards were added: `!(context has probe)` on each permit,
`context has probe` on each forbid. Nothing else changed; no condition was
rewritten.

| file | origin |
|---|---|
| `policy.cedar` | derived here, as above: 2 `@tier` permits + 29 `@id` forbids + 2 `@assembly` forbids, 28 KB against the adopted file's 102 KB |
| `expected_ids.json` | the adopted file's ids and tiers verbatim, plus `"shape": "permit-decides"` |
| `manifest.json`, `fetchplan.json`, `contract.json` | byte-identical to `../cedar_family_spend` — the hoist is the same, so the derivation contract is the same |
| `guidance.json` | byte-identical to `../family_spend` and `../cedar_family_spend` |

It is hand-shaped, and it claims nothing beyond its tests: no bridge theorem
covers it, and the "certified modulo the derivation contract" statement
`contract.json` makes about the adopted file is not transferred by
re-shaping. What the tests establish is that it decides exactly as the
adopted file and the Rego and CEL twins do, on every scenario in
`tests/test_three_engine_differential.py`, and reports the same failed
check ids.

Why it exists: the forbid-only shape spends three quarters of its bytes
restating the other tier, and Cedar has no way to factor that. This file is
what the same policy looks like when the permits decide and the forbids
only explain — the shape a hand author would write. SECURITY.md records
the one property that differs: in this shape an empty policy set denies.

## Rebuild

Nothing to build — `policy.cedar` is interpreted source. To re-derive it
from a changed adopted file, repeat the cut described above; the
differential is the check that nothing was lost.

# Fixture provenance — cedar_family_spend_compact (Cedar, permit-decides, supplied)

The fourth twin of `family_spend`: the same 29 conditions and two tiers as
`../cedar_family_spend`, in the permit-decides shape. **Supplied by an
external policy-authoring toolchain** — the same one behind the adopted
`family_spend_*` bundles — as the verbatim output of its permit-decides
emitter target over its own `family_spend` core. It replaced, on
2026-10-27, a version of this file that this repository had derived
mechanically from the adopted forbid-only text; the supplied emission and
that derivation agreed on all 29 `@id` forbids and both `@tier` permits as
parsed ASTs, and differed only in the two `@assembly` clauses, where the
supplier deliberately drops the negated-other-tier suffix the derivation
had kept (in this shape the assembly clause is reached only in the probe
pass, which runs only on a denial, so there is no tier for it to avoid
firing against).

Digest of the **unedited** emission, as the supplier published it:

```
sha256  fed720ac1ba04b187af8ef5758a2930345dc3e6e0c3829fadee78e0b28e30f44
bytes   22,605
```

Generator-internal names in the header comment were anonymized for this
public release, as with every supplied bundle here; nothing executable
changed. The substitutions, so the digest can be reproduced from the
anonymized file: the generator's name in the first line → "an external
policy-authoring toolchain"; the bridge theorem's section reference →
"The supplier's bridge theorem"; the safety predicate's internal name →
"(the supplier's safety predicate)"; the emitter's internal name →
"The emitter"; two lemma names → "the supplier's covers-of-singleton
lemma" / "the supplier's fold-applies lemma"; the goal's module path →
`policybundle.examples.family_spend`; one section cross-reference removed.

| file | origin |
|---|---|
| `policy.cedar` | supplied, header anonymized as above: 2 `@tier` permits (`solo`, then `full_chain`) + 29 `@id` forbids (each also `@tier`) + 2 `@assembly` forbids; 22.6 KB against the adopted forbid-only file's 101.8 KB |
| `expected_ids.json` | the adopted file's ids and tiers verbatim, plus `"shape": "permit-decides"` |
| `manifest.json`, `fetchplan.json`, `contract.json` | byte-identical to `../cedar_family_spend` — the hoist is the same, so the derivation contract is the same |
| `guidance.json` | byte-identical to `../family_spend` and `../cedar_family_spend` |

Not yet the supplier's shipped artifact: its tool emits this text beside
the forbid-only one, and its shipped bundle is still forbid-only pending
the certificate composing through the new assembly lemma. It is adopted
here now as the permit-decides member of the three-engine differential,
so that the supplier's emitter is checked against the loader and all
fourteen scenarios before it ships, and so that a disagreement surfaces
in a fixture rather than in a proof. The "certified modulo the derivation
contract" statement in `contract.json` is the supplier's claim about the
forbid-only emission; it is not asserted of this file until the supplier
says so.

Why the shape exists: the forbid-only shape spends 85% of its bytes
restating the other tier, negated, in every leaf, and Cedar has no way to
factor that. More to the point, in this shape every degenerate case
denies — an empty set, a raising permit, a probe key on the wrong pass —
where in forbid-only an empty or half-loaded set is a permit. SECURITY.md
records that difference.

## Rebuild

Nothing to build — `policy.cedar` is interpreted source. To re-adopt a new
emission: take the supplier's permit-decides output unedited, record its
sha256 above, apply the header substitutions listed above, and run
`tests/test_three_engine_differential.py` and `tests/test_cedar_policy.py`;
the loader's completeness check and the fourteen scenarios are the
acceptance test.

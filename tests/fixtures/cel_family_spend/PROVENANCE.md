# Fixture provenance — cel_family_spend (CEL policy-engine proof of concept)

Not derived from any external toolchain. Hand-authored directly for this
repository, to prove the `PolicyEngine` Protocol is real — a second,
independently-implemented engine, evaluated against the *same*
`manifest.json`/`fetchplan.json`/`guidance.json` contract the OPA/Rego
engine uses, producing the same enforcement semantics for the same test
scenarios. See NOTES.md ("CEL as a Second Policy Engine — Design and
Semantic-Parity Mapping") for the full design and the empirical findings
against `cel-python` that this bundle's authoring style follows.

Mirrors the teaching `family_spend` scenario exactly (kid's signed request,
solo tier ≤ $10, full-chain tier with a parent's authorization up to $200,
did-free single-trust-root signing) — same tiers, same check ids, same
`manifest.json`/`fetchplan.json` (copied verbatim; both are already fully
engine-agnostic, zero changes needed). `guidance.json`'s `sentence`/
`remedy_class`/`id`/`call_guards` are unchanged; only `condition` is
rewritten from Rego's failure-form (`not signed_by(...)`) to CEL's
positive-assertion form (`verify_eddsa(...)`) — `condition` is never
programmatically read by `render_denial`, so this is a documentation-only
polarity difference between engine profiles, not a functional one.

**No `has()` guards in `checks.cel.json`.** Not an oversight: this bundle's
`manifest.json` (like the original it mirrors) puts `authorizationVC` in
the root `required` list unconditionally — it predates the guard-aware-
manifest treatment (`family_spend_prod` got that fix; this teaching bundle
never did) — so every field every check references is contractually always
present. A guard-aware bundle (conditionally-required fields) **must** guard
those fields with `has()` in every check that touches them, or an absent
field raises and the whole query fails closed per the engine's design rule.
`tests/test_cel_policy.py` proves that fail-closed behavior directly against
a minimal ad-hoc check, since this fixture's own contract never exercises
absence.

## Rebuild

Nothing to build — `checks.cel.json` is plain, interpreted CEL source; there
is no compile step, no toolchain, no private dependency. Edit the file
directly.

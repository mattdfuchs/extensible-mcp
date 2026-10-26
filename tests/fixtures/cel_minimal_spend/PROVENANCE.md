# Fixture provenance — cel_minimal_spend (CEL twin of the smallest teaching bundle)

Not derived from any external toolchain. Hand-authored directly for this
repository: the same five conditions as `../minimal_spend`, written as CEL
expressions in `checks.cel.json` — a map from check id to one expression,
plus the tier each id belongs to. Each check is written in the object form,
`{"expr", "sentence"}`, so the file carries its own denial text: the inline
form a hand author uses instead of a `guidance.json`. The sentences are the
same five as the guidance file's, and `tests/test_fixture_corpus.py` holds
them identical; with the guidance present they are not read. `manifest.json` / `fetchplan.json` /
`guidance.json` are byte-identical to the Rego twin's; the one engine-
specific file is the only one that differs.

- `"package": "policybundle.examples.minimal_spend"` (`.`-separated in CEL,
  `/`-separated in the Rego entrypoint paths — cosmetic, same policy).
- `verify_eddsa` is a CEL function the proxy registers, the same host
  primitive the Rego twin calls as `io.jwt.verify_eddsa`.
- No `has()` guards: every field a check reads is in the manifest's root
  `required`, so none can be absent when a check runs. A bundle with a
  conditionally-required credential has to guard it — see
  `cel_family_spend_invoice`.
- `"id_scheme": "named-split"`, no `guidance_digest` (hand-authored, not a
  supplier artifact).

## Rebuild

Nothing to build — `checks.cel.json` is interpreted source. Edit it
directly; `tests/test_fixture_corpus.py` checks its ids against the
guidance and `tests/test_minimal_bundle_differential.py` checks its
decisions against the other two engines.

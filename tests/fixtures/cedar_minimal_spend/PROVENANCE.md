# Fixture provenance — cedar_minimal_spend (Cedar twin of the smallest teaching bundle)

Not derived from any external toolchain. Hand-authored directly for this
repository, and the one Cedar bundle in the corpus written to be read: one
condition per `forbid`, in the plain form, rather than the generated form
`cedar_family_spend` carries. Same five conditions as `../minimal_spend`.

What Cedar forces, and nothing else, is different here:

- **The signature is hoisted.** Cedar has no host-function extension point,
  so `fetchplan.json` gains one `derive` entry: `verify_eddsa` folded over
  the single trusted key (`requesterJwk`), projecting the keys that verified
  into `requestVCJwsRequesterJwkKeyWitnesses`. The `signed_by` forbid tests
  that the trusted key is in that witness set. The entry declares its
  primitive in the plan's `primitives` block, and `manifest.json` lists the
  derived field under `derived_fields` and in `properties` — never in
  `required`, since the fold yields `[]` when nothing verified.
- **Permit decides, forbid explains** — the shape `expected_ids.json`
  declares. One `@tier("solo")` permit carries the five conditions once,
  guarded `!(context has probe)`; one `forbid` per check carries only its
  own condition, annotated `@id` with the guidance id it reports under and
  guarded `context has probe`; one `@assembly("solo")` forbid with no `@id`
  fires, in the probe pass only, when the tier's inputs are incomplete. The
  proxy evaluates the file twice: without `probe` the permit decides and an
  empty set denies; with `probe: true`, on a denial, the fired forbids are
  the failed checks. `expected_ids.json` lists the five ids and the one tier
  the loader must find as forbids, and the one tier it must find as a
  permit; the guards it checks on every call. The forbid-only shape the
  external toolchain emits is the other one the loader accepts;
  `../cedar_family_spend` is in it.
- `guidance.json` is byte-identical to the Rego twin's, so a denial renders
  the same sentence whichever engine produced the id.

`tests/test_fixture_corpus.py` asserts the manifest and fetch plan differ
from the Rego twin's by exactly the derived field and its entry;
`tests/test_minimal_bundle_differential.py` holds the decisions to the
other two engines'. No bridge theorem is claimed for a hand-authored
bundle: the guarantee is the derivation contract written down, which is
the most any Cedar bundle here claims (see SECURITY.md).

## Rebuild

Nothing to build — `policy.cedar` is interpreted source. Edit it directly,
keeping `expected_ids.json` in step: the loader refuses a mismatch, and a
forbid or permit that loses its `probe` guard is a fault at the first call
that would have exercised it.

# Fixture provenance — cedar_family_spend (Cedar, teaching scenario)

The Cedar counterpart of `family_spend` (Rego) and `cel_family_spend`
(CEL): the same kid's-request / parent's-authorization scenario, the same
29 named check ids, decided by a third engine. It is the first Cedar bundle
in this repo, and the one the three-engine differential in
`tests/test_three_engine_differential.py` runs on.

The rules were **supplied by an external policy-authoring toolchain**, the
same one behind the adopted `family_spend_*` bundles, emitted from its own
`family_spend` core. Generator-internal names in the header comment and in
`contract.json` have been anonymized for this public release, as with every
supplied bundle here; nothing executable changed. The three
engine-independent files are *not* taken from the supplier wholesale, and
the split is deliberate:

| file | origin |
|---|---|
| `policy.cedar` | supplied: 1 unconditional `permit` + 29 leaf `forbid`s (`@id`) + 2 assembly `forbid`s (`@assembly`) |
| `expected_ids.json` | supplied: the 29 ids and 2 assembly tiers the loader must find |
| `contract.json` | supplied: the 5 derivation obligations — the host's half of the guarantee |
| `manifest.json` | supplied: the shared teaching manifest **plus** 5 derived-field properties, never `required`; `definitions` identical except that the three claims objects are open |
| `fetchplan.json` | supplied: the shared teaching plan's 9 entries **verbatim**, plus 5 `derive` entries and a `primitives` block |
| `guidance.json` | **this repo's own**, byte-identical to `family_spend/guidance.json` |

`guidance.json` is ours because the teaching `family_spend` family carries
hand-authored sentences and conditions (see that fixture's PROVENANCE.md)
while sharing the supplier's id scheme position for position. The ids are
the join; the sentences are what a denial renders. Taking the supplier's
guidance would have made this bundle render differently from its two
siblings for the same failed check, which is exactly what the differential
exists to catch. `tests/test_fixture_corpus.py` pins the byte identity and
that `expected_ids.json` names the guidance's ids and no others.

`manifest.json` and `fetchplan.json` are the supplier's because the policy
was proven safe against *that* manifest's shape: every emitted condition
was checked, before emission, to be unable to raise over any input the
manifest admits. Substituting a manifest would void that. The differences
from the shared teaching files are the ones Cedar forces and nothing else,
which the corpus test asserts entry by entry.

## Why this bundle is shaped the way it is

- **Cedar cannot call a function.** No host-function extension point exists,
  by design — it would destroy the decidability that makes Cedar
  analysable. So the seven leaves that verify a signature or hash a request
  cannot run inside the policy. Each becomes a `derive` entry: the fetch
  plan folds `verify_eddsa` over a one-element candidate list built from
  `trustRootJwk` and projects the key of every candidate that verified, and
  the rule tests `context.<field>.contains(context.trustRootJwk)`. The
  `sha256` of the request's JWS is derived the same way, bare.
- **The witness set must be exact.** `contract.json` states the obligation
  per derived field: exactly the candidates for which the primitive holds,
  and no other value. The direction that matters is over-inclusion — a set
  that is too large makes a forbid fail to fire, so Cedar allows where the
  source denies. `DeriveResolver._fold` collects on `is True`, by identity
  and not truthiness; `tests/test_cedar_policy.py` pins that a primitive
  answering any truthy non-`True` value yields no witness.
- **Forbid-only, one policy per reason leaf.** A leaf's forbid fires on
  *this leaf failed, and every other tier failed too*, so a solo-tier
  failure does not veto a full-chain permit; the union over leaves is
  exactly "the source denies", and each fired forbid is a reason with the
  same id Rego's `failed_checks` reports. A leaf fires on **present and
  false**, matching Rego's undefined-is-not-reported, so Cedar never
  announces "signature is invalid" for a credential nobody supplied.
- **One `@assembly` forbid per tier** closes the hole that leaves: if every
  tier fails *only* through missing inputs, nothing is present-and-false
  and the base permit would stand. It carries no `@id` because it is not a
  reason the guidance has a sentence for; `cedar_policy.py` drops it from
  `failed_checks`, and `guidance.render_denial` explains the absent
  credential from `call_guards` as it already does for the other engines.
- **`expected_ids.json` is load-bearing, not belt-and-braces.** Forbid-only
  means an empty policy set allows everything, so a bundle that half-loads
  is a silent permit. The loader refuses a policy set that does not carry
  exactly one forbid per listed id and one per listed assembly tier.

## What the supplier claims, and what it does not

The policy's header says **NOT FAITHFUL (yet)**, on purpose. What the
supplier has proven is *no fail-open*: no emitted condition can raise, so
no forbid can be skipped. What is **not** yet generated is the bridge
theorem — that a Cedar decision over exact witness sets equals the source
policy's decision on the un-hoisted input. Until it is, this bundle's
guarantee is the derivation contract *written down*, not proved: certified
modulo `contract.json`, never "verified Cedar".

The supplier ran its own nine-scenario differential, `cedarpy` against
`opa eval`, with this repo's `DeriveResolver` in the middle — nine for nine
on decision and reported reason set. This repo's differential runs
fourteen scenarios across all three engines against the real signed
evidence the other fixtures use, and additionally compares the *rendered*
denial, which the supplier's cannot since the guidance here is ours.

- Package: none. Cedar has no package construct; the bundle loader labels
  the entrypoints with the directory name (`cedar_family_spend/allow`,
  `cedar_family_spend/failed_checks`). No `deny_reason` — like a CEL
  bundle, denials render only through guidance.
- Primitives: `verify_eddsa` (key-consuming, folded) and `sha256` (pure,
  bare) — both already in `fetchplan.default_primitives`, the same
  module-level functions the Rego engine imports as host builtins.
- `guidance.json` records `"id_scheme": "named-split"` and carries no
  `guidance_digest`, because that field names a supplier artifact and
  this file is not one.

## Rebuild

Nothing to build — `policy.cedar` is interpreted source. Reproducing the
emitted files requires the supplying toolchain, which is not part of this
repository; if replacing them with a newer emission, keep `guidance.json`
as this repo's own, re-run the anonymization pass over the header comment
and `contract.json`, and verify against `test_three_engine_differential.py`
before and after, as with every supplied bundle here.

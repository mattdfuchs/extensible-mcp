# Fixture provenance — cel_family_spend_prod (CEL twin, production VC verification)

## Re-pinned 2026-11-05 to upstream `364c4da` (the token/evidence seam)

This section supersedes the entrypoint and count lines below where they
differ; those are kept as the history of the pin.

- **`account_bound`**, one check per tier (`solo/full_chain.requester_membership.account_bound`), binds the session's
  identity-provider account to the member whose key signed: vacuous with no
  principal, a plain equality when the issuer's subjects are the accounts
  themselves, else membership in the admin-signed `accounts` list
  (`{idp, account}`, `additionalProperties: false`). Two `caller`-sourced
  plan entries, `callerIdp` (`iss`) and `callerAccount` (`sub`), read the
  proxy's principal and never the call. 32 → 34 ids.
- **`deny_reason` is gone** upstream: the sentences live in `guidance.json`
  and every denial renders through it, on every engine alike.
- `guidance_digest.value = "c776a057d78a4999"`, shared by the Rego, CEL and
  Cedar twins, whose `manifest.json`, `fetchplan.json` and `guidance.json`
  are byte-identical.
- Behavioural rows for the seam on this bundle are this repository's own
  (`tests/test_vc_policy.py`), built with its signing harness, run on all three engines.

Supplied by an external policy-authoring toolchain — the CEL twin of
`family_spend_prod`, emitted from the same common core rather than
translated from the Rego bundle. Because both artifacts are generated,
their agreement on every production scenario in `tests/test_vc_policy.py`
(parametrized to run against both engines) isn't two authors corroborating
each other. What it does check is that two quite different runtimes — a
WASM module and in-process CEL evaluation — reach the same decision
through the same host builtins, and that the check ids, which come from
separate expansions that neither language validates, still line up. All of
it against this repo's own engines rather than a harness belonging to the
supplier.

This is the second CEL bundle in this repo governing a production-shaped
(not teaching) policy, after `cel_family_spend_invoice`; the whole
`VCPolicyFilter` path — wallet bundles, adapter, `did:web` admin-key
resolution, assembly, evaluation — now runs end to end on CEL as well as
on the wasm engine. See `cel_family_spend`'s own PROVENANCE.md for the
hand-authored teaching bundle this is not related to.

- Pinned at upstream commit `d114d32` (the check-split regeneration), the
  same pin as the Rego twin; upstream's history for this directory is
  empty after that commit, so the artifact adopted is exactly the
  `d114d32` one. `guidance.json` carries `"id_scheme": "named-split"` and
  `guidance_digest.value = "b5f8d6314061d4c3"` — the same digest as the
  Rego twin's, because `manifest.json`, `fetchplan.json` and
  `guidance.json` are byte-identical between the two. That byte-identity
  was measured with `cmp` against `tests/fixtures/family_spend_prod/` at
  adoption and held for all three files; `tests/test_fixture_corpus.py`
  asserts it from then on. `checks.cel.json`'s `tiers`/`checks`/`guards`
  and `fetchplan.json`'s `deciding_checks` all join on the same named ids,
  which is the cross-engine agreement this fixture exists to check. The
  split takes `member_of` to `issued_by_trusted_admin` / `signed_by_key` /
  `sub_matches` / `within_window` at each of its three sites (23 → 32
  checks, tiers 11 + 21, 16 authored and 16 mechanical); see the Rego
  twin's PROVENANCE.md for the one sentence corrected upstream on the way,
  and for `full_chain.authorization_vc.hash_binds`, which stays welded by
  rule on both engines.
- Package: `policybundle.examples.family_spend_prod` — anonymized for
  this public release, matching `family_spend_prod`'s own package name
  (both bundles' entrypoints resolve under the same logical name; only
  the `/`-vs-`.` separator differs, an artifact of how OPA's `-e` compile
  flags vs. a plain JSON `"package"` field each spell the same path).
  That one line is the only difference from the upstream file.
- Entrypoints: `allow`, `failed_checks` — **no `deny_reason`**; CEL
  bundles in this repo never expose one (see
  `cel_policy.CelPolicy.entrypoints()`), so `VCPolicyFilter` renders every
  denial from `failed_checks` through the guidance layer on this engine.
- Host functions: `key_from_did_key`, `verify_eddsa`, `sha256` — the CEL
  twins of the Rego bundle's `key_from_did_key`, `io.jwt.verify_eddsa` and
  `crypto.sha256`. All three were already in
  `cel_policy.default_cel_functions`; adopting this bundle needed no new
  host function.
- `guards` (`checks.cel.json`'s own field, distinct from the Rego bundle's
  `fetchplan.json` guard entries but serving the same purpose) excludes
  the full-chain tier's `authorizationVC` / `approverMembership` checks
  when those credentials are genuinely absent at or under the $10
  threshold — exercised by `test_vc_policy.py`'s solo-tier scenarios on
  both engines.
- **Cross-engine divergence, not a defect in this bundle:** on a signed
  request whose claims carry no `merchant` at all (an out-of-contract
  input the proxy's own fetch-plan assembly never produces), this bundle
  raises `PolicyEvaluationError` from `solo.request_vc.merchant_matches` —
  this repo's CEL engine is fail-closed on any exception, with no attempt
  to distinguish a structural fault from an evidentiary denial. The Rego
  twin evaluates around the undefined reference and returns a
  `failed_checks` set that is silent on the merchant ids. Same class as the
  divergence documented in `cel_family_spend_invoice`'s PROVENANCE.md;
  `test_vc_policy.py::test_undefined_reference_comparison_emits_no_failed_check_id`
  is therefore Rego-only and says so.

## Rebuild

Nothing to build — `checks.cel.json` is plain, interpreted CEL source;
there is no compile step. If replacing this fixture with a newer version
from the supplier, verify byte-for-byte against `test_vc_policy.py`
before and after, same discipline as every other supplied bundle here.

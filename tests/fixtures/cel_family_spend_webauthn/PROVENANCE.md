# Fixture provenance — cel_family_spend_webauthn (CEL twin, WebAuthn approval leg)

## Re-pinned 2026-11-05 to upstream `364c4da` (the token/evidence seam)

This section supersedes the entrypoint and count lines below where they
differ; those are kept as the history of the pin.

- **`account_bound`**, one check per tier (`solo/full_chain.requester_membership.account_bound`), binds the session's
  identity-provider account to the member whose key signed: vacuous with no
  principal, a plain equality when the issuer's subjects are the accounts
  themselves, else membership in the admin-signed `accounts` list
  (`{idp, account}`, `additionalProperties: false`). Two `caller`-sourced
  plan entries, `callerIdp` (`iss`) and `callerAccount` (`sub`), read the
  proxy's principal and never the call. 30 → 32 ids.
- **`deny_reason` is gone** upstream: the sentences live in `guidance.json`
  and every denial renders through it, on every engine alike.
- `guidance_digest.value = "3d5e03e7a83b5b65"`, shared by the Rego, CEL and
  Cedar twins, whose `manifest.json`, `fetchplan.json` and `guidance.json`
  are byte-identical.
- Behavioural rows for the seam on this bundle are this repository's own
  (`tests/test_webauthn_policy.py`), built with its signing harness, run on all three engines.

> **Not wired into any live path**, for the same reason as the Rego twin:
> `spend_challenge_binds` ties the assertion to `(tool, amountCents,
> merchant)` and nothing else, so one assertion authorizes unlimited
> identical calls. The canonical string is a shared wire constant the two
> engines must agree on, so reinstating this rail means re-issuing both
> twins together. See `family_spend_webauthn`'s PROVENANCE.md.

Supplied by an external policy-authoring toolchain — the CEL twin of
`family_spend_webauthn`, emitted from the same common core rather than
translated from the Rego bundle. Because both artifacts are generated,
their agreement on every scenario in `tests/test_webauthn_policy.py`
(parametrized to run against both engines) isn't two authors corroborating
each other. What it does check is that two quite different runtimes — a
WASM module and in-process CEL evaluation — reach the same decision
through the same host builtins, and that the check ids, which come from
separate expansions that neither language validates, still line up. All of
it against this repo's own engines rather than a harness belonging to the
supplier.

This is the third CEL bundle in this repo governing a production-shaped
(not teaching) policy, after `cel_family_spend_invoice` and
`cel_family_spend_prod`, and the first whose authorization side is a
passkey assertion rather than a wallet credential; with it, every
production-shaped Rego bundle in `tests/fixtures/` has a CEL twin. See
`cel_family_spend`'s own PROVENANCE.md for the hand-authored teaching
bundle this is not related to.

- Pinned at upstream commit `c40ca70` (2026-10-22), **not** the `d114d32`
  (2026-10-20) pin the other five adopted Rego/CEL bundles are on, because
  this directory did not exist at `d114d32`: upstream's CEL emission for
  this policy had not been run until `c40ca70`, the commit that added it.
  Upstream's own account of why is worth keeping — one atom, the challenge
  canonicalization, had no CEL template, and the emitter's documented
  fallback would have exported it as an eighth host obligation, putting
  the one check that binds an approval to an exact call where nothing can
  check it; `c40ca70` gave the atom its template instead, so the string is
  built in-policy (see the canonicalization bullet below). Upstream's
  history for this directory after `c40ca70` is one commit, `784028a`
  (2026-10-23), which touched only the directory's `README.md` (not
  adopted); the four files here are byte-identical at `c40ca70` and at
  upstream HEAD as of adoption. The Rego twin's directory has no commits
  after `d114d32`, so the two pins name the same policy state, and the
  pairing below is between artifacts upstream regenerated from one core.
- `guidance.json` carries `"id_scheme": "named-split"` and
  `guidance_digest.value = "22c0b6689dcbbc13"` — the same digest as the
  Rego twin's, because `manifest.json`, `fetchplan.json` and
  `guidance.json` are byte-identical between the two. That byte-identity
  was measured with `cmp` against `tests/fixtures/family_spend_webauthn/`
  at adoption and held for all three files; `tests/test_fixture_corpus.py`
  asserts it from then on. `checks.cel.json`'s `tiers`/`checks`/`guards`
  and `fetchplan.json`'s `deciding_checks` all join on the same named ids,
  which is the cross-engine agreement this fixture exists to check. The
  split takes `member_of` and `enrolled_as` each to four leaves
  (`issued_by_trusted_admin` / `enrolled_by_trusted_admin`,
  `signed_by_key`, `sub_matches`, `within_window`): 30 checks, tiers
  11 + 19, 15 authored and 15 mechanical, the same 30 ids in the same
  order as the Rego bundle's `failed_checks`.
- Package: `policybundle.examples.family_spend_webauthn` — anonymized for
  this public release, matching `family_spend_webauthn`'s own package name
  (both bundles' entrypoints resolve under the same logical name; only
  the `/`-vs-`.` separator differs, an artifact of how OPA's `-e` compile
  flags vs. a plain JSON `"package"` field each spell the same path).
  That one line is the only difference from the upstream file.
- Entrypoints: `allow`, `failed_checks` — **no `deny_reason`**; CEL
  bundles in this repo never expose one (see
  `cel_policy.CelPolicy.entrypoints()`), so every denial is rendered from
  `failed_checks` through the guidance layer on this engine.
- Host functions: `base64url_decode`, `base64url_encode_no_pad`,
  `key_from_did_key`, `parse_json`, `sha256`, `verify_eddsa` and
  `verify_webauthn` — the CEL twins of the Rego bundle's `base64url.decode`,
  `base64url.encode_no_pad`, `key_from_did_key`, `json.unmarshal`,
  `crypto.sha256`, `io.jwt.verify_eddsa` and `verify_webauthn`. All seven
  were already in `cel_policy.default_cel_functions`; adopting this bundle
  needed no new host function. `verify_webauthn` is registered only when a
  relying-party id is configured, and `PolicyBundle.load` has no parameter
  for CEL functions, so `test_webauthn_policy.py` assembles the CEL bundle
  by hand around a `CelPolicy` built with the rp id — the same mechanism
  `test_invoice_policy.py` uses for the invoice twin.
- **The canonicalization, in CEL.** `full_chain.approval.spend_challenge_binds`
  builds the challenge pre-image in-policy as
  `"<version-tag>|spend|" + tool + "|" + string(amountCents) + "|" + merchant`,
  where the Rego bundle joins with `concat` and formats with `format_int`.
  The two spellings agree over the integers, and the operand reaching
  either is asserted to be one by the proxy's plan load (a float operand
  to the derive copies is a load-time fault), not by the manifest's
  `"type": "integer"` — upstream corrected its own README on that point in
  `784028a`. The version tag is a shared wire constant both twins and the
  proxy's approval page must agree on, kept as supplied.
- `guards` (`checks.cel.json`'s own field, distinct from the Rego bundle's
  `fetchplan.json` guard entries but serving the same purpose) excludes
  the full-chain tier's `approval` / `approverEnrollment` checks when
  those are genuinely absent at or under the $10 threshold — exercised by
  `test_webauthn_policy.py`'s solo-tier scenarios on both engines.
- **Cross-engine divergence, not a defect in this bundle:** loaded with no
  relying-party id configured, the Rego twin refuses to load — the wasm
  module imports `verify_webauthn`, and a missing import is a load-time
  `PolicyEvaluationError`. A CEL bundle declares no imports, so this twin
  loads, and the absence surfaces on the first call that reaches
  `full_chain.approval.webauthn_verified`: an undeclared-reference
  evaluation fault, which the filter fails closed on with the rendered
  "could not be evaluated" denial, the detail going to the proxy log.
  The solo tier, which never reaches the function, still decides
  normally. Same fail-closed outcome, different moment; measured at
  adoption, and `test_webauthn_policy.py::test_load_without_rp_id_fails_closed`
  is therefore Rego-only and says so. Every scenario in that file runs on
  both engines, the challenge canonicalization included, and none
  diverged: the invoice and prod twins' undefined-reference divergence
  has no counterpart here, because this file never feeds the policy an
  out-of-contract input.

## Rebuild

Nothing to build — `checks.cel.json` is plain, interpreted CEL source;
there is no compile step. If replacing this fixture with a newer version
from the supplier, verify byte-for-byte against `test_webauthn_policy.py`
before and after, same discipline as every other supplied bundle here.

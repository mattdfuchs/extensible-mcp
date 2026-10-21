# Fixture provenance — family_spend_prod (production VC verification)

A faithful multi-key policy: per-signer `did:key`, a `did:web` admin
membership chain, nested W3C-VC claims, a solo tier at or under $10 and a
full-chain tier up to $200 requiring a co-signed authorization bound to the
request by `jti` + a SHA-256 hash of the request's compact JWS.

Supplied by an external policy-authoring toolchain (not `opa`/Rego source
written by hand for this repo, unlike the teaching `family_spend`/`classifier`
fixtures). The package identifier and any generator-internal comments have
been anonymized for this public release; behavior is unchanged and verified
byte-for-byte against this repository's own test suite (`test_vc_policy.py`,
`test_augment.py`, `test_issuer.py`) before and after the anonymization —
`allow`/`deny_reason`/`failed_checks` are confirmed identical, not merely
believed to be.

- Re-pinned to upstream commit `d114d32` (the check-split regeneration,
  93 → 126 ids across the five upstream bundles). `guidance.json` carries
  `"id_scheme": "named-split"` and `guidance_digest.value = "b5f8d6314061d4c3"` —
  the digest changes exactly when any id, sentence, condition, remedy class
  or tier structure does, so a future re-pin compares that one line rather
  than diffing sentence text. `d114d32` is `0ecfdd2` (the settled sentence
  fix, see below) plus the digest field; nothing else in this directory
  changed between them.
- **The split.** Each parameterised helper that transitively reaches a
  crypto or codec primitive is split into its body's conjuncts, with the
  caller's actuals substituted. Here `member_of` dissolves into
  `issued_by_trusted_admin`, `signed_by_key`, `sub_matches` and
  `within_window` at each of its three sites: 23 → 32 ids, 16 authored and
  16 mechanical.
  A denial that read *"a membership credential does not chain to a trusted
  admin"* now names which link broke. Two shapes stay welded by rule and
  are asserted single in `tests/test_fixture_corpus.py`: a crypto
  application already inside a quantifier is not lifted out, and a
  single-literal body inlines to itself.
- **One inherited sentence was corrected upstream rather than welded back.**
  `signed_by_key(jws, jwk)` takes a key the policy does not derive — the
  proxy resolves it from the issuer's `did:web`, and only for issuers in the
  trusted set — so an untrusted issuer yields no key and the leaf fails
  *without* the signature being wrong. Its sentence is therefore *"a
  credential's signature could not be verified against its issuer's key"*,
  true in both states. `signed_by_did_key` keeps the flat *"signature is
  invalid"*, because there the policy derives the key itself and absence
  is impossible. Row one of that finding is pinned in
  `tests/test_vc_policy.py::test_untrusted_admin_denies`.
- Package: `policybundle.examples.family_spend_prod`
- Entrypoints: `allow`, `deny_reason`, `failed_checks` (32 named check ids,
  tiers 11 + 21 — `solo.*` on the solo tier and `full_chain.*` on the
  full-chain tier, e.g. `solo.request_vc.signed_by_did_key`,
  `full_chain.approver_membership.issued_by_trusted_admin`). Ids are opaque
  join keys — nothing in `src/` parses one.
- Uses the custom host builtin `key_from_did_key` (plus stock
  `io.jwt.verify_eddsa`, `crypto.sha256`)
- `manifest.json`'s wallet-supplied claim-body definitions
  (`Request*`/`Auth*`/`Mem*`) are open (`additionalProperties: true`) —
  real wallets emit open-world W3C VCs the policy reads only specific paths
  from; the root, `CallArgs`, and the envelope wrappers stay closed

No rebuild recipe is included here — reproducing this bundle from scratch
requires the supplying toolchain, which is not part of this repository. The
supplied `policy.rego` and its companion `manifest.json`/`fetchplan.json`/
`guidance.json` are the artifact; this repo's test suite is what verifies
they behave as documented.

`policy.wasm` is compiled here from that supplied `policy.rego` with
`opa build -t wasm` (opa 1.17.1), the three entrypoints above, and the
supplier's own `capabilities.json` for this bundle — needed to declare the
custom `key_from_did_key` builtin. That capabilities file is a *build
input*, not part of the artifact, and is deliberately not committed to this
fixture; `wasm_policy.default_builtins`'s docstrings give the exact
signatures if one has to be regenerated independently.

# Fixture provenance — family_spend_webauthn (WebAuthn approval leg)

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
  and every denial renders through it, on every engine alike. The wasm is rebuilt from the supplied `policy.rego` with `opa build -t wasm` (opa 1.17.1), entrypoints `allow` and `failed_checks`, and the supplier's uncommitted `capabilities.json`.
- `guidance_digest.value = "3d5e03e7a83b5b65"`, shared by the Rego, CEL and
  Cedar twins, whose `manifest.json`, `fetchplan.json` and `guidance.json`
  are byte-identical.
- Behavioural rows for the seam on this bundle are this repository's own
  (`tests/test_webauthn_policy.py`), built with its signing harness, run on all three engines.

> **Not wired into any live path.** Tested here, but no runnable proxy loads
> it. `spend_challenge_binds` ties the assertion to `(tool, amountCents,
> merchant)` and nothing else, so the challenge is a pure function of the
> terms: one assertion authorizes unlimited identical calls, with no
> per-transaction component to make it single-use. `family_spend_invoice`
> avoids this by taking the challenge over a whole merchant-signed invoice,
> which carries a `nonce`. Reinstating this rail means giving the challenge a
> per-approval nonce — a change to the canonical string, so the Rego and the
> compiled `policy.wasm` move together, and the bundle wants re-issuing rather
> than a local rebuild. Kept as the artifact to fix.

The approval-leg counterpart to `family_spend_prod`: request side is
identical (did:key request VC + did:web admin membership chain);
authorization side is a passkey assertion, verified by the host builtin
`verify_webauthn` (ES256/P-256 signature, rpId, UP/UV flags — 4-arg, origin
checked in-policy) plus an in-policy challenge binding
(`spend_challenge_binds`) tying the signed challenge to the exact
`(tool, amountCents, merchant)` of the call. An admin-signed enrollment VC
binds `credentialId → (role, publicKey)`.

Supplied by an external policy-authoring toolchain, same as
`family_spend_prod`. The package identifier and generator-internal comments
have been anonymized for this public release; behavior verified byte-for-byte
against this repository's own test suite (`test_webauthn_policy.py`) before
and after.

- Re-pinned to upstream commit `d114d32` (the check-split regeneration,
  93 → 126 ids across the five upstream bundles). `guidance.json` carries
  `"id_scheme": "named-split"` and `guidance_digest.value = "22c0b6689dcbbc13"` —
  the digest changes exactly when any id, sentence, condition, remedy class
  or tier structure does, so a future re-pin compares that one line rather
  than diffing sentence text. `d114d32` is `0ecfdd2` (the settled sentence
  fix, see below) plus the digest field; nothing else in this directory
  changed between them.
- **The split.** Each parameterised helper that transitively reaches a
  crypto or codec primitive is split into its body's conjuncts, with the
  caller's actuals substituted. Here `member_of` and `enrolled_as` each
  dissolve into four (`issued_by_trusted_admin` / `enrolled_by_trusted_admin`,
  `signed_by_key`, `sub_matches`, `within_window`): 21 → 30 ids, 15 authored
  and 15 mechanical.
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
- Package: `policybundle.examples.family_spend_webauthn`
- Entrypoints: `allow`, `deny_reason`, `failed_checks` (30 named check ids,
  tiers 11 + 19 — `solo.*` / `full_chain.*`, e.g.
  `full_chain.approval.spend_challenge_binds`). Ids are opaque join keys.
- Uses the custom host builtins `verify_webauthn`, `key_from_did_key` (plus
  stock `io.jwt.verify_eddsa`, `crypto.sha256`, `base64url.encode_no_pad` —
  a standard OPA builtin the wasm target still leaves host-provided)
- `manifest.json`'s wallet-supplied claim bodies are open, same reasoning
  as `family_spend_prod`
- The challenge-binding constant is `"<version-tag>|spend|" + tool + "|" +
  amountCents + "|" + merchant`, hex-ASCII SHA-256, base64url — a byte-exact
  protocol both this policy and the proxy's own WebAuthn approval page must
  agree on; kept as originally supplied rather than renamed, since it is a
  shared wire constant, not descriptive text

No rebuild recipe is included; see `family_spend_prod`'s note.

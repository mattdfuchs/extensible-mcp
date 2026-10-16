# Fixture provenance — family_spend_webauthn (WebAuthn approval leg)

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

- Re-pinned to upstream commit `0ee19df` (the named-check-id regeneration).
  `guidance.json` carries `"id_scheme": "named-welded"`.
- Package: `policybundle.examples.family_spend_webauthn`
- Entrypoints: `allow`, `deny_reason`, `failed_checks` (21 named check ids,
  tiers 8 + 13 — `solo.*` / `full_chain.*`, e.g.
  `full_chain.approval.spend_challenge_binds`). Replaces the earlier
  positional `t0.c*` / `t1.c*` scheme; ids are opaque join keys, so the
  authored sentences and every rendered denial are unchanged.
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

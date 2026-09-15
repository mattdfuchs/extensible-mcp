# Fixture provenance — family_spend_webauthn (WebAuthn approval leg)

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

- Package: `policybundle.examples.family_spend_webauthn`
- Entrypoints: `allow`, `deny_reason`, `failed_checks` (21 ids, tiers 8 + 13)
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

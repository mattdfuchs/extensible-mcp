# Fixture provenance — family_spend_invoice (invoice-bound approval leg)

Supplied by an external policy-authoring toolchain, same as `family_spend_prod`
and `family_spend_webauthn`. Certifies the negotiate → invoice → passkey →
settle → fulfill demo's authorization decision. Supersedes an earlier
hand-authored reference bundle of the same name that proved the concept
before the certified version existed; that reference is preserved in this
repo's git history, not in this directory.

Brings the merchant-signed invoice and both approval legs under one policy:
a raw Ed25519 signature over the invoice's exact canonical bytes (no
re-canonicalization in-policy — the policy parses the invoice fields from
the *signed* string itself via `json.unmarshal`, never a re-serialized
copy), verified against a closed trusted-merchant set, plus **two**
WebAuthn passkey legs — child always required, parent required only above
the $10 solo-approval threshold — each independently bound to
`hash(invoice.canonical)`. No wallet-issued VC anywhere in this bundle:
the demo's actual approval service gates both roles on WebAuthn alone.

- Re-pinned to upstream commit `d114d32` (the check-split regeneration,
  93 → 126 ids across the five upstream bundles). `guidance.json` carries
  `"id_scheme": "named-split"` and `guidance_digest.value = "f2712452315e4b1f"` —
  the digest changes exactly when any id, sentence, condition, remedy class
  or tier structure does, so a future re-pin compares that one line rather
  than diffing sentence text. `d114d32` is `0ecfdd2` (the settled sentence
  fix, see below) plus the digest field; nothing else in this directory
  changed between them.
- **The split.** Each parameterised helper that transitively reaches a
  crypto or codec primitive is split into its body's conjuncts, with the
  caller's actuals substituted. Here `enrolled_as` dissolves into
  `enrolled_by_trusted_admin`, `signed_by_key`, `sub_matches` and
  `within_window` at each of its three sites: 23 → 32 ids, 23 authored and
  9 mechanical. `signed_by_trusted_merchant` stays a single check — the
  crypto application sits inside the relational join over `trustedMerchants`.
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
- Package: `policybundle.examples.family_spend_invoice` — anonymized for
  this public release (originally the supplier's own package path);
  behavior verified byte-for-byte against this repository's own test
  suite (`test_invoice_policy.py`) before and after
- Entrypoints: `allow`, `deny_reason`, `failed_checks` (32 named check ids,
  tiers 12 + 20 — `solo.*` / `dual.*`, e.g.
  `solo.invoice.signed_by_trusted_merchant`,
  `dual.parent_approval.invoice_challenge_binds`). Ids are opaque join keys.
- **This re-pin closes the `tool` gap.** The manifest previously declared
  no `tool` property while being `additionalProperties: false` at the root,
  so an assembled envelope — which always carries `tool` — failed
  validation on every call, allowed or denied, and the demo's invoice
  filter had to run with `validate_input=False`. `InvoiceSpendInput` now
  declares `tool`, required and call-sourced. `policy.rego` does not read
  it: there is no signed statement of a tool name anywhere in this flow to
  bind it against, and the approval challenge already covers the whole
  canonical invoice. Declared-not-read is exactly what validation needs,
  and the standing exception retires with this re-pin
  (`test_invoice_policy.py::test_a_genuine_call_validates_against_the_manifest`).
- Uses the custom host builtins `verify_webauthn` (existing) and
  `verify_ed25519_raw` (new — verifies a raw Ed25519
  signature over an exact string with both signature and key as
  base64url raw bytes, not a JOSE/JWK object, since a merchant is not a
  did:key/did:web trust-network member)
- **`trustedMerchants` is a list of `{merchantId, key}` entries, not a
  keyed map.** The supplier's toolchain has no dynamic key projection, so
  the merchant lookup is a relational join over the list — trust is
  checked on `(merchantId, key)` together, not either alone, which also
  means a valid signature from a trusted key attributed to the *wrong*
  merchant correctly fails (`tests/test_invoice_policy.py`'s
  `test_invoice_attributed_to_a_different_merchant_denies`). This changed
  the input shape from an earlier hand-authored draft of this bundle,
  which used a keyed map — noted here since it's the one thing about this
  bundle that isn't a drop-in replacement for that draft.
- `manifest.json`'s `PasskeyEnrollment`/`PasskeyClaims` definitions match
  `family_spend_webauthn`'s; `Invoice`/`TrustedMerchant`/`InvoiceArgs` are
  specific to this bundle
- **Cross-engine note, found while adopting this bundle:** on a genuinely
  missing *unconditionally-required* field (e.g. `childApproval` entirely
  absent — not the guarded-optional `parentApproval`, which both engines
  handle identically), the Rego engine's undefined-
  propagation silently evaluates around it and returns a `failed_checks`
  set without raising, while the CEL engine raises
  `PolicyEvaluationError` (this repo's own fail-closed-by-design
  behavior for CEL). Not a live risk — the proxy's fetch-plan assembly
  always supplies every unconditionally-required field or fails before
  the policy is ever queried — but a real, documented divergence between
  the two engines on out-of-contract input, pinned down by
  `tests/test_invoice_policy.py::test_engines_diverge_on_a_genuinely_missing_required_field`
  rather than left as an untested assumption.
- No rebuild recipe is included; see `family_spend_prod`'s note. The
  supplier's own capabilities declarations for `verify_webauthn` and
  `verify_ed25519_raw` (needed to `opa build -t wasm --capabilities …`
  from this policy) are 3-4 string args each, boolean result — see
  `wasm_policy.default_builtins`'s docstrings for the exact signatures if
  regenerating a capabilities file independently.

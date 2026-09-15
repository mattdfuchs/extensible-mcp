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

- Package: `policybundle.examples.family_spend_invoice` — anonymized for
  this public release (originally the supplier's own package path);
  behavior verified byte-for-byte against this repository's own test
  suite (`test_invoice_policy.py`) before and after
- Entrypoints: `allow`, `deny_reason`, `failed_checks` (23 ids, tiers 9 + 14)
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

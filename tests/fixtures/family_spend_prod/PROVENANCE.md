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

- Re-pinned to upstream commit `0ee19df` (the named-check-id regeneration).
  `guidance.json` carries `"id_scheme": "named-welded"` — the scheme marker
  is emitted from a single constant upstream, so it names the artifact
  rather than being inferred from the id count here.
- Package: `policybundle.examples.family_spend_prod`
- Entrypoints: `allow`, `deny_reason`, `failed_checks` (23 named check ids,
  `solo.*` on the solo tier and `full_chain.*` on the full-chain tier, e.g.
  `solo.request_vc.signed_by_did_key`,
  `full_chain.approver_membership.member_of`). Ids are opaque join keys —
  nothing in `src/` parses one — so the rename from the earlier positional
  scheme (tier index + check index) is a pure relabeling: the authored
  sentences, and so every rendered denial, are unchanged.
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

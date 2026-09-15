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

- Package: `policybundle.examples.family_spend_prod`
- Entrypoints: `allow`, `deny_reason`, `failed_checks` (23 tier-local check
  ids, `t0.c0`–`t0.c7` / `t1.c0`–`t1.c14`)
- Uses the custom host builtin `key_from_did_key` (plus stock
  `io.jwt.verify_eddsa`, `crypto.sha256`)
- `manifest.json`'s wallet-supplied claim-body definitions
  (`Request*`/`Auth*`/`Mem*`) are open (`additionalProperties: true`) —
  real wallets emit open-world W3C VCs the policy reads only specific paths
  from; the root, `CallArgs`, and the envelope wrappers stay closed

No rebuild recipe is included here — reproducing this bundle from scratch
requires the supplying toolchain, which is not part of this repository. The
compiled `policy.wasm` and its companion `manifest.json`/`fetchplan.json`/
`guidance.json` are the artifact; this repo's test suite is what verifies
they behave as documented.

# Fixture provenance — family_spend (Rego teaching bundle)

Not derived from any external toolchain. Hand-authored directly for this
repository — a plain, minimal Rego bundle exercising the same scenario as
its CEL sibling (`../cel_family_spend/checks.cel.json`): a kid's signed
request, a solo tier at or under $10 needing only the request, and a
full-chain tier up to $200 needing a parent's authorization bound to the
request by `jti` + a SHA-256 hash of the request's compact JWS. Single
trust root (a JWK passed directly, no did:key/did:web resolution — that
layer lives in the more elaborate production-shaped bundles), matching the
CEL sibling's simplifications exactly so the two are directly comparable.

- Package: `policybundle.examples.family_spend` (`/` as the entrypoint
  path separator, `.` in the CEL sibling's own `package` field — cosmetic,
  same policy).
- Entrypoints: `allow`, `deny_reason`, `failed_checks` (23 tier-local check
  ids, `t0.c0`–`t0.c7` / `t1.c0`–`t1.c14`, matching the CEL sibling's ids
  exactly).
- `manifest.json`/`fetchplan.json`/`guidance.json` are shared verbatim with
  the CEL sibling — both already fully engine-agnostic, nothing here is
  Rego-specific.
- Uses only stock OPA builtins (`io.jwt.verify_eddsa`, `crypto.sha256`) —
  no custom host builtin, so no `capabilities.json` is needed to build it.

## Rebuild

```sh
opa build -t wasm \
  -e policybundle/examples/family_spend/allow \
  -e policybundle/examples/family_spend/deny_reason \
  -e policybundle/examples/family_spend/failed_checks \
  policy.rego -o /tmp/fsp.tar.gz
tar xzf /tmp/fsp.tar.gz -C /tmp policy.wasm
cp /tmp/policy.wasm .
```

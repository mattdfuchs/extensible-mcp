# Fixture provenance — minimal_spend (Rego, the smallest teaching bundle)

Not derived from any external toolchain. Hand-authored directly for this
repository as the bundle the README's "Authoring a bundle" section walks
through: one tier, one signed request, one spending cap. The request's
signature is checked against a single key the deployment config supplies
(`requesterJwk`); the request must be current, name this tool and these
exact arguments, and the amount must be at or under $10. Nothing else — no
memberships, no second credential, no DID resolution. Those live in
`family_spend` and the production-shaped bundles; this one exists to be
read in full.

- Package: `policybundle.examples.minimal_spend`.
- Entrypoints: `allow`, `failed_checks`, `deny_reason`. The `deny_reason`
  rules carry the same five sentences as `guidance.json`: they are Rego's
  inline form of the text, what the proxy falls back to for a bundle that
  ships no guidance. With guidance present they are not read, and
  `tests/test_fixture_corpus.py` holds the two sets of sentences identical.
- Five named check ids, one tier (`solo.*`), `"id_scheme": "named-split"`
  in `guidance.json`, which carries no `guidance_digest` because that field
  names a supplier artifact and this bundle is not one.
- `manifest.json` / `fetchplan.json` / `guidance.json` are shared verbatim
  with the CEL twin (`../cel_minimal_spend`). The Cedar twin
  (`../cedar_minimal_spend`) shares the guidance verbatim and adds to the
  other two only what Cedar forces; `tests/test_fixture_corpus.py` pins
  exactly which differences those are.
- `tests/test_minimal_bundle_differential.py` runs the three twins against
  the same signed artifacts and holds them to one verdict and one set of
  failed-check ids.
- Uses only `io.jwt.verify_eddsa`, supplied by the proxy as a host builtin;
  no `capabilities.json` is needed to build it.

## Rebuild

```sh
P=policybundle/examples/minimal_spend
opa build -t wasm -e $P/allow -e $P/failed_checks -e $P/deny_reason policy.rego -o /tmp/ms.tar.gz
tar xzf /tmp/ms.tar.gz -C /tmp policy.wasm
cp /tmp/policy.wasm .
```

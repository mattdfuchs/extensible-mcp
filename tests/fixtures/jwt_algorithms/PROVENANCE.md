# Fixture provenance — jwt_algorithms (Rego, synthetic)

Not derived from any external toolchain, and not a policy bundle: there is
no manifest, fetch plan or guidance here, and nothing loads it through
`PolicyBundle`. It is one entrypoint per host-supplied JWS verifier --
`io.jwt.verify_es256`, `io.jwt.verify_rs256` and, as the control,
`io.jwt.verify_eddsa` -- each applied to `input.jws` and `input.jwk`, so
`tests/test_jwt_algorithms.py` can drive the real wasm import path of each:
the builtin name the compiled module asks its host for, the operands as OPA
marshals them across the boundary, and the boolean the host hands back.

It is committed rather than built in the test because CI does not have
`opa`; every compiled fixture in this directory exists for that reason.

- Package: `policybundle.examples.jwt_algorithms`.
- Entrypoints: `es256`, `rs256`, `eddsa`, each a bare builtin call.
- Uses only stock OPA builtin *names*, so no `capabilities.json` is needed
  to build it; the implementations are the proxy's own host imports
  (`wasm_policy.default_builtins`), which is what the test is about.
- The keys and tokens the test feeds it are generated at run time with
  joserfc; none is committed.

## Rebuild

```sh
P=policybundle/examples/jwt_algorithms
opa build -t wasm -e $P/es256 -e $P/rs256 -e $P/eddsa policy.rego -o /tmp/ja.tar.gz
tar xzf /tmp/ja.tar.gz -C /tmp policy.wasm
cp /tmp/policy.wasm .
```

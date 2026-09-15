# Fixture provenance — classifier (stage-one bundle selection)

Not derived from any external toolchain. Hand-authored directly for this
repository. A `Descriptor -> decision` policy (string-valued, no crypto
host builtins, so no `capabilities.json` is needed to build it).

## Rebuild

```sh
opa build -t wasm -e policybundle/examples/classifier/decision \
  policy.rego -o /tmp/cls.tar.gz
tar xzf /tmp/cls.tar.gz -C /tmp policy.wasm
cp /tmp/policy.wasm .
```

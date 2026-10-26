# Hand-authored for this repository. Not derived from any external toolchain
# -- see PROVENANCE.md. Not a policy bundle: no manifest, fetch plan or
# guidance, and nothing loads it through PolicyBundle. One entrypoint per
# host-supplied JWS verifier, so the wasm import path of each -- the name the
# module asks the host for, the arguments as OPA marshals them, the boolean
# back -- is exercised against a real compiled module in CI, where `opa` is
# not installed to build one on the fly.
package policybundle.examples.jwt_algorithms

import rego.v1

es256 := io.jwt.verify_es256(input.jws, input.jwk)

rs256 := io.jwt.verify_rs256(input.jws, input.jwk)

eddsa := io.jwt.verify_eddsa(input.jws, input.jwk)

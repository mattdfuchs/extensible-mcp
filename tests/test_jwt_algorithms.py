# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""ES256 and RS256 JWS verification, in all three engines (#57).

Before these, every registered signature primitive was Ed25519, so a
hand-written policy over an ordinary identity-provider token -- or an AP2
checkout JWT, which is ES256 by spec -- had nothing to call, and in Rego the
attempt failed at load because OPA's JWT builtins are host-supplied under
the wasm target. The contract is ``io.jwt.verify_eddsa``'s, verbatim: a
problem with the *evidence* (the token) is ``False``; a problem with the
*configured key* is a ``HostBuiltinError``, because a verifier that cannot
read its key must fail closed and never as a quiet deny.

Keys and tokens are generated here with joserfc; nothing is committed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from joserfc import jws
from joserfc.jwk import ECKey, OKPKey, RSAKey

from extensible_mcp.fetchplan import (
    KEY_CONSUMING_PRIMITIVES,
    FetchContext,
    FetchExecutor,
    default_primitives,
)
from extensible_mcp.wasm_policy import (
    HostBuiltinError,
    OpaWasmPolicy,
    default_builtins,
)

FIXTURE = Path(__file__).parent / "fixtures" / "jwt_algorithms" / "policy.wasm"
PKG = "policybundle/examples/jwt_algorithms"


@pytest.fixture(scope="module")
def ec_key():
    return ECKey.generate_key("P-256")


@pytest.fixture(scope="module")
def rsa_key():
    return RSAKey.generate_key(2048)


@pytest.fixture(scope="module")
def okp_key():
    return OKPKey.generate_key("Ed25519")


def _pub(key) -> str:
    """The public JWK as a config string, the shape a trust root is handed in."""
    return json.dumps(key.as_dict(private=False))


def _sign(alg: str, key, payload: bytes = b'{"sub":"alice"}') -> str:
    return jws.serialize_compact({"alg": alg}, payload, key, algorithms=[alg])


@pytest.fixture(scope="module")
def es256_token(ec_key) -> str:
    return _sign("ES256", ec_key)


@pytest.fixture(scope="module")
def rs256_token(rsa_key) -> str:
    return _sign("RS256", rsa_key)


@pytest.fixture(scope="module")
def eddsa_token(okp_key) -> str:
    return _sign("Ed25519", okp_key)


# --------------------------------------------------------------------------- #
# The plain builtins -- the one implementation every engine shares
# --------------------------------------------------------------------------- #

CASES = [("es256", "io.jwt.verify_es256", "ec_key", "es256_token"),
         ("rs256", "io.jwt.verify_rs256", "rsa_key", "rs256_token")]


@pytest.mark.parametrize("name,builtin,key_fx,token_fx", CASES, ids=["es256", "rs256"])
def test_a_valid_token_verifies_against_its_public_key(request, name, builtin, key_fx, token_fx):
    verify = default_builtins()[builtin]
    key, token = request.getfixturevalue(key_fx), request.getfixturevalue(token_fx)
    assert verify(token, _pub(key)) is True
    assert verify(token, key.as_dict(private=False)) is True  # object JWK accepted


@pytest.mark.parametrize("name,builtin,key_fx,token_fx", CASES, ids=["es256", "rs256"])
def test_a_tampered_or_foreign_token_is_a_denial_not_a_fault(request, name, builtin, key_fx, token_fx):
    verify = default_builtins()[builtin]
    key, token = request.getfixturevalue(key_fx), request.getfixturevalue(token_fx)
    header, payload, sig = token.split(".")
    assert verify(f"{header}.{payload}.{sig[:-4]}AAAA", _pub(key)) is False
    other = ECKey.generate_key("P-256") if name == "es256" else RSAKey.generate_key(2048)
    assert verify(_sign("ES256" if name == "es256" else "RS256", other), _pub(key)) is False
    assert verify("not.a.token", _pub(key)) is False
    assert verify(None, _pub(key)) is False
    assert verify(123, _pub(key)) is False


def test_the_wrong_algorithm_is_false_not_a_fault(ec_key, rsa_key, okp_key, es256_token, rs256_token, eddsa_token):
    """An ES256 token handed to the RS256 verifier, and every other cross,
    is a token that did not verify -- evidence, never a system fault. The
    header's ``alg`` is the attacker's to write; the verifier's algorithm is
    fixed by which builtin the policy called."""
    b = default_builtins()
    assert b["io.jwt.verify_rs256"](es256_token, _pub(rsa_key)) is False
    assert b["io.jwt.verify_es256"](rs256_token, _pub(ec_key)) is False
    assert b["io.jwt.verify_es256"](eddsa_token, _pub(ec_key)) is False
    assert b["io.jwt.verify_rs256"](eddsa_token, _pub(rsa_key)) is False
    assert b["io.jwt.verify_eddsa"](es256_token, _pub(okp_key)) is False


def test_no_key_is_a_denial(es256_token, rs256_token):
    b = default_builtins()
    assert b["io.jwt.verify_es256"](es256_token, None) is False
    assert b["io.jwt.verify_rs256"](rs256_token, None) is False


@pytest.mark.parametrize("builtin,token_fx", [("io.jwt.verify_es256", "es256_token"),
                                              ("io.jwt.verify_rs256", "rs256_token")])
def test_an_unreadable_key_fails_closed(request, builtin, token_fx):
    """The key is deployment configuration. If it is present but cannot be
    read, the verifier is broken, and a broken verifier must not read as a
    quiet deny the operator never hears about."""
    verify = default_builtins()[builtin]
    token = request.getfixturevalue(token_fx)
    with pytest.raises(HostBuiltinError, match="unparseable JWK"):
        verify(token, "this is not json")
    with pytest.raises(HostBuiltinError, match="JWK must be object, string, or null"):
        verify(token, 5)
    with pytest.raises(HostBuiltinError, match="invalid JWK"):
        verify(token, '{"kty": "EC"}')


def test_one_key_family_per_verifier(ec_key, rsa_key, es256_token, rs256_token):
    """An EC key handed to the RS256 verifier is a malformed key *for that
    primitive*, exactly as an EC key handed to ``io.jwt.verify_eddsa`` is:
    a fault, not a denial, because it is the configuration that is wrong."""
    b = default_builtins()
    with pytest.raises(HostBuiltinError, match="verify_rs256: invalid JWK"):
        b["io.jwt.verify_rs256"](rs256_token, _pub(ec_key))
    with pytest.raises(HostBuiltinError, match="verify_es256: invalid JWK"):
        b["io.jwt.verify_es256"](es256_token, _pub(rsa_key))
    with pytest.raises(HostBuiltinError, match="verify_eddsa: invalid JWK"):
        b["io.jwt.verify_eddsa"](es256_token, _pub(ec_key))


# --------------------------------------------------------------------------- #
# Rego: the real wasm import path, against a committed module
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def wasm() -> OpaWasmPolicy:
    return OpaWasmPolicy(FIXTURE, builtins=default_builtins())


def _result(out):
    assert out and "result" in out[0], out
    return out[0]["result"]


def test_the_wasm_module_imports_all_three_verifiers(wasm):
    assert set(wasm.entrypoints()) == {f"{PKG}/es256", f"{PKG}/rs256", f"{PKG}/eddsa"}


def test_wasm_verifies_each_algorithm_through_its_own_host_import(
    wasm, ec_key, rsa_key, okp_key, es256_token, rs256_token, eddsa_token
):
    assert _result(wasm.query({"jws": es256_token, "jwk": _pub(ec_key)}, f"{PKG}/es256")) is True
    assert _result(wasm.query({"jws": rs256_token, "jwk": _pub(rsa_key)}, f"{PKG}/rs256")) is True
    assert _result(wasm.query({"jws": eddsa_token, "jwk": _pub(okp_key)}, f"{PKG}/eddsa")) is True


def test_wasm_denies_a_cross_algorithm_token(wasm, ec_key, rsa_key, es256_token, rs256_token):
    assert _result(wasm.query({"jws": rs256_token, "jwk": _pub(ec_key)}, f"{PKG}/es256")) is False
    assert _result(wasm.query({"jws": es256_token, "jwk": _pub(rsa_key)}, f"{PKG}/rs256")) is False


def test_wasm_fails_closed_on_an_unreadable_key(wasm, es256_token):
    from extensible_mcp.wasm_policy import PolicyEvaluationError

    with pytest.raises(PolicyEvaluationError, match="unparseable JWK"):
        wasm.query({"jws": es256_token, "jwk": "not json"}, f"{PKG}/es256")


def test_a_module_needing_the_verifier_fails_at_load_without_it():
    """The pre-#57 failure, pinned: a policy that calls the builtin against a
    host that does not register it is refused at load, not at the first call."""
    from extensible_mcp.wasm_policy import PolicyEvaluationError

    builtins = default_builtins()
    del builtins["io.jwt.verify_es256"]
    with pytest.raises(PolicyEvaluationError, match="io.jwt.verify_es256"):
        OpaWasmPolicy(FIXTURE, builtins=builtins)


# --------------------------------------------------------------------------- #
# CEL: the adapters are the same implementation behind celtypes
# --------------------------------------------------------------------------- #


def test_cel_adapters_verify_and_deny_like_the_builtins(ec_key, rsa_key, es256_token, rs256_token):
    from celpy import celtypes

    from extensible_mcp.cel_policy import default_cel_functions

    f = default_cel_functions()
    assert bool(f["verify_es256"](celtypes.StringType(es256_token), celtypes.StringType(_pub(ec_key)))) is True
    assert bool(f["verify_rs256"](celtypes.StringType(rs256_token), celtypes.StringType(_pub(rsa_key)))) is True
    assert bool(f["verify_es256"](celtypes.StringType(rs256_token), celtypes.StringType(_pub(ec_key)))) is False
    assert bool(f["verify_rs256"](celtypes.StringType(es256_token), celtypes.NullType())) is False


def test_cel_check_over_an_es256_token_decides(tmp_path, ec_key, es256_token):
    """End to end through the CEL engine: one check, the new function."""
    from extensible_mcp.cel_policy import CelPolicy, default_cel_functions

    spec = {
        "engine": "cel-v1",
        "package": "policybundle.examples.es256",
        "tiers": [{"tier": 0, "checks": ["solo.token.signed_by"]}],
        "checks": {"solo.token.signed_by": "verify_es256(input.token, input.issuerJwk)"},
    }
    path = tmp_path / "checks.cel.json"
    path.write_text(json.dumps(spec))
    policy = CelPolicy(path, functions=default_cel_functions())
    allow = "policybundle.examples.es256/allow"
    assert policy.query({"token": es256_token, "issuerJwk": _pub(ec_key)}, allow) == [{"result": True}]
    header, payload, sig = es256_token.split(".")
    assert policy.query({"token": f"{header}.{payload}.{sig[:-4]}AAAA", "issuerJwk": _pub(ec_key)}, allow) == [
        {"result": False}
    ]


# --------------------------------------------------------------------------- #
# derive: key-consuming, foldable, projecting the key that verified
# --------------------------------------------------------------------------- #


def test_both_are_key_consuming_primitives():
    assert {"verify_es256", "verify_rs256"} <= KEY_CONSUMING_PRIMITIVES
    assert {"verify_es256", "verify_rs256"} <= set(default_primitives())


@pytest.mark.parametrize("fn,key_fx,token_fx", [("verify_es256", "ec_key", "es256_token"),
                                                ("verify_rs256", "rsa_key", "rs256_token")])
async def test_a_fold_projects_exactly_the_key_that_verified(request, fn, key_fx, token_fx):
    """The Cedar path: the primitive folded over candidate keys, projecting
    the ones that verified into a witness set the rule tests a relation over.
    One good key and one stranger: the witness set names the good one only."""
    key, token = request.getfixturevalue(key_fx), request.getfixturevalue(token_fx)
    stranger = ECKey.generate_key("P-256") if fn == "verify_es256" else RSAKey.generate_key(2048)
    plan = {
        "input": "TokenInput",
        "primitives": {fn: {"class": "key-consuming"}},
        "entries": [
            {"field": "token", "source": {"kind": "config"}},
            {"field": "issuers", "source": {"kind": "config"}},
            {"field": "tokenWitnesses", "source": {
                "kind": "derive", "fn": fn,
                "over": {"$input": "issuers"},
                "args": [{"$input": "token"}, {"$item": "key"}],
                "project": "id",
            }},
        ],
    }
    ctx = FetchContext(config={
        "token": token,
        "issuers": [{"id": "idp-a", "key": _pub(key)}, {"id": "idp-b", "key": _pub(stranger)}],
    })
    assembled = await FetchExecutor().assemble(plan, ctx)
    assert assembled["tokenWitnesses"] == ["idp-a"]

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""End-to-end tests for the WASM policy engine against a real compiled artifact.

The fixture ``tests/fixtures/family_spend/policy.wasm`` is built offline
with ``opa build -t wasm`` from the committed ``family_spend`` policy (which
uses ``io.jwt.verify_eddsa`` + ``crypto.sha256`` as host imports). These tests
sign a genuine Ed25519 credential chain — the same ``Ed25519`` JOSE alg the
identity layer signs with — and assert the policy's ``allow`` decision is driven
by the Python-supplied crypto built-ins.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from extensible_mcp.wasm_policy import (
    HostBuiltinError,
    OpaWasmPolicy,
    PolicyEvaluationError,
    default_builtins,
)
from tests import vc_helpers as vc
from tests.vc_helpers import KID_DID, PARENT_DID, TRUST_DID

FIXTURE = Path(__file__).parent / "fixtures" / "family_spend" / "policy.wasm"
PKG = "policybundle/examples/family_spend"
ALLOW = f"{PKG}/allow"
DENY_REASON = f"{PKG}/deny_reason"


@pytest.fixture(scope="module")
def signing_key():
    return vc.new_key()


@pytest.fixture(scope="module")
def trust_jwk(signing_key) -> str:
    return vc.public_jwk(signing_key)


def _sign(payload: dict, key) -> str:
    return vc.sign(payload, key)


def _within(now: int = 100) -> dict:
    return {"nbf": 0, "exp": 9999999999}


def _solo_input(signing_key, trust_jwk, *, amount: int = 500) -> dict:
    """A valid kid-only request (amount <= $10 → solo path)."""
    args = {"amountCents": amount, "merchant": "acme"}
    req_jws = _sign({"sub": KID_DID}, signing_key)
    mem_jws = _sign({"sub": KID_DID}, signing_key)
    return {
        "tool": "send",
        "arguments": args,
        "requestVC": {
            "jws": req_jws,
            "claims": {
                "jti": "r1", "iss": KID_DID, "action": "send",
                "arguments": args, **_within(),
            },
        },
        # Present but unused on the solo branch; kept so nothing is missing.
        "authorizationVC": {
            "jws": req_jws,
            "claims": {"jti": "r1", "iss": PARENT_DID, "requestHash": "0" * 64, **_within()},
        },
        "requesterMembership": {
            "jws": mem_jws,
            "claims": {"iss": TRUST_DID, "sub": KID_DID, "role": "kid", **_within()},
        },
        "approverMembership": {
            "jws": mem_jws,
            "claims": {"iss": TRUST_DID, "sub": PARENT_DID, "role": "parent", **_within()},
        },
        "trustRootDID": TRUST_DID,
        "trustRootJwk": trust_jwk,
        "now": 100,
    }


def _full_chain_input(signing_key, trust_jwk, *, amount: int = 5000) -> dict:
    """A valid kid-request + parent-authorization (amount > $10 → full chain).

    Exercises ``crypto.sha256``/``bound_to``: the authorization's ``requestHash``
    must equal ``sha256(requestVC.jws)`` and the two share a ``jti``.
    """
    base = _solo_input(signing_key, trust_jwk, amount=amount)
    req_jws = base["requestVC"]["jws"]
    auth_jws = _sign({"sub": PARENT_DID}, signing_key)
    base["authorizationVC"] = {
        "jws": auth_jws,
        "claims": {
            "jti": "r1",  # bound to the request's jti
            "iss": PARENT_DID,
            "requestHash": hashlib.sha256(req_jws.encode()).hexdigest(),
            **_within(),
        },
    }
    return base


def _result_bool(result) -> bool:
    # OPA result-set shape: [{"result": <value>}]
    assert result and "result" in result[0], result
    return result[0]["result"]


@pytest.fixture(scope="module")
def policy() -> OpaWasmPolicy:
    return OpaWasmPolicy(FIXTURE)


def test_entrypoints_present(policy):
    eps = policy.entrypoints()
    assert ALLOW in eps and DENY_REASON in eps


def test_solo_path_allows(policy, signing_key, trust_jwk):
    result = policy.query(_solo_input(signing_key, trust_jwk), ALLOW)
    assert _result_bool(result) is True


def test_full_chain_path_allows(policy, signing_key, trust_jwk):
    # Forces crypto.sha256 + bound_to via the parent-authorization branch.
    result = policy.query(_full_chain_input(signing_key, trust_jwk), ALLOW)
    assert _result_bool(result) is True


def test_tampered_signature_denies(policy, signing_key, trust_jwk):
    bad = _solo_input(signing_key, trust_jwk)
    jws = bad["requestVC"]["jws"]
    bad["requestVC"]["jws"] = jws[:-6] + ("A" if jws[-1] != "A" else "B") * 6
    # Verification fails -> the built-in returns False -> policy denies.
    # Crucially this is a denial, NOT a PolicyEvaluationError.
    result = policy.query(bad, ALLOW)
    assert _result_bool(result) is False


def test_tampered_signature_reports_reason(policy, signing_key, trust_jwk):
    bad = _solo_input(signing_key, trust_jwk)
    jws = bad["requestVC"]["jws"]
    bad["requestVC"]["jws"] = jws[:-6] + ("A" if jws[-1] != "A" else "B") * 6
    reasons = _result_bool(policy.query(bad, DENY_REASON))
    assert any("signature is invalid" in r for r in reasons), reasons


def test_amount_over_solo_limit_without_auth_denies(policy, signing_key, trust_jwk):
    # > $10 but no valid authorization chain (default authorizationVC) → deny.
    over = _solo_input(signing_key, trust_jwk, amount=5000)
    assert _result_bool(policy.query(over, ALLOW)) is False


def test_malformed_jwk_fails_closed_not_silent_deny(policy, signing_key, trust_jwk):
    """The load-bearing distinction: a built-in *erroring* must surface as
    PolicyEvaluationError (fail closed), never as a quiet allow=false."""
    bad = _solo_input(signing_key, trust_jwk)
    bad["trustRootJwk"] = "this is not a json jwk"
    with pytest.raises(PolicyEvaluationError):
        policy.query(bad, ALLOW)


def test_null_evidence_denies_not_errors(policy, signing_key, trust_jwk):
    """A missing/null credential JWS is invalid *evidence* → a clean deny,
    not a fail-closed PolicyEvaluationError."""
    bad = _solo_input(signing_key, trust_jwk)
    bad["requestVC"]["jws"] = None
    assert _result_bool(policy.query(bad, ALLOW)) is False


def test_garbage_evidence_denies_not_errors(policy, signing_key, trust_jwk):
    bad = _solo_input(signing_key, trust_jwk)
    bad["requestVC"]["jws"] = "not.a.valid.jws"
    assert _result_bool(policy.query(bad, ALLOW)) is False


def test_unknown_entrypoint_raises(policy, signing_key, trust_jwk):
    with pytest.raises(PolicyEvaluationError):
        policy.query(_solo_input(signing_key, trust_jwk), "policybundle/examples/family_spend/nope")


def test_key_from_did_key_roundtrips_and_verifies():
    """The did:key-derived JWK verifies a JWS signed by that key — the
    composition key_from_did_key -> verify_eddsa the production policy uses."""
    from extensible_mcp.wasm_policy import _key_from_did_key, _verify_eddsa

    key = vc.new_key()
    did = vc.did_key(key)
    jwk = _key_from_did_key(did)
    assert jwk is not None and jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519"

    token = vc.sign({"hello": "world"}, key)
    assert _verify_eddsa(token, jwk) is True  # object JWK accepted
    # a different signer's token does not verify against this derived key
    assert _verify_eddsa(vc.sign({"x": 1}, vc.new_key()), jwk) is False


def test_key_from_did_key_malformed_returns_none_not_raises():
    from extensible_mcp.wasm_policy import _key_from_did_key, _verify_eddsa

    for bad in [None, "not-a-did", "did:key:zNOT_BASE58_0!!", "did:web:example.com"]:
        assert _key_from_did_key(bad) is None
    # and a None key denies (does not raise) — so a bad did:key in one tier
    # never traps evaluation of another
    assert _verify_eddsa("a.b.c", None) is False


def test_verify_eddsa_still_fails_closed_on_corrupt_config_string():
    from extensible_mcp.wasm_policy import _verify_eddsa

    with pytest.raises(HostBuiltinError):
        _verify_eddsa("a.b.c", "this is not json")


def test_custom_builtin_error_propagates():
    """A host built-in raising HostBuiltinError fails closed with its message."""

    def boom(_jws, _jwk):
        raise HostBuiltinError("synthetic verify failure")

    builtins = default_builtins()
    builtins["io.jwt.verify_eddsa"] = boom
    pol = OpaWasmPolicy(FIXTURE, builtins=builtins)

    key = vc.new_key()
    trust = vc.public_jwk(key)
    with pytest.raises(PolicyEvaluationError, match="synthetic verify failure"):
        pol.query(_solo_input(key, trust), ALLOW)


# --------------------------------------------------------------------------- #
# verify_ed25519_raw — the merchant-invoice-signature builtin:
# a raw Ed25519 signature over an exact byte string, key and signature both
# base64url raw bytes rather than a JOSE/JWK object — distinct from
# io.jwt.verify_eddsa because a merchant isn't a did:key/did:web trust-network
# member with a JOSE-wrapped key.
# --------------------------------------------------------------------------- #


def _ed25519_raw_keypair():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def _b64url(b: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def test_verify_ed25519_raw_valid_signature_verifies():
    from extensible_mcp.wasm_policy import _verify_ed25519_raw

    private_key, public_key = _ed25519_raw_keypair()
    message = '{"merchantId":"dominos","totalCents":400}'
    signature = private_key.sign(message.encode())
    key_b64url = _b64url(public_key.public_bytes_raw())

    assert _verify_ed25519_raw(message, _b64url(signature), key_b64url) is True


def test_verify_ed25519_raw_tampered_message_denies():
    from extensible_mcp.wasm_policy import _verify_ed25519_raw

    private_key, public_key = _ed25519_raw_keypair()
    signature = private_key.sign(b'{"totalCents":400}')
    key_b64url = _b64url(public_key.public_bytes_raw())

    # same signature, different message — must not verify
    assert _verify_ed25519_raw(
        '{"totalCents":40000}', _b64url(signature), key_b64url
    ) is False


def test_verify_ed25519_raw_wrong_key_denies():
    from extensible_mcp.wasm_policy import _verify_ed25519_raw

    private_key, _ = _ed25519_raw_keypair()
    _, other_public = _ed25519_raw_keypair()
    message = "an invoice"
    signature = private_key.sign(message.encode())

    assert _verify_ed25519_raw(
        message, _b64url(signature), _b64url(other_public.public_bytes_raw())
    ) is False


def test_verify_ed25519_raw_none_key_denies_not_errors():
    """An untrusted/absent merchant key is a clean denial — same treatment as
    a missing JWK in _verify_eddsa — not a system fault."""
    from extensible_mcp.wasm_policy import _verify_ed25519_raw

    assert _verify_ed25519_raw("anything", "c2ln", None) is False


def test_verify_ed25519_raw_malformed_key_fails_closed():
    """A configured trusted-merchant key that doesn't decode to a valid
    Ed25519 public key is a deployment fault, not a policy decision."""
    from extensible_mcp.wasm_policy import _verify_ed25519_raw

    with pytest.raises(HostBuiltinError):
        _verify_ed25519_raw("anything", "c2ln", "not-valid-base64url-key!!!")


def test_verify_ed25519_raw_non_string_evidence_denies_not_errors():
    from extensible_mcp.wasm_policy import _verify_ed25519_raw

    _, public_key = _ed25519_raw_keypair()
    key_b64url = _b64url(public_key.public_bytes_raw())

    assert _verify_ed25519_raw(None, "c2ln", key_b64url) is False
    assert _verify_ed25519_raw("a message", None, key_b64url) is False
    assert _verify_ed25519_raw("a message", "not-valid-base64!!!", key_b64url) is False


def test_repeated_queries_do_not_grow_the_wasm_heap():
    """The OPA heap is a bump allocator with no free. Each query marshals
    data, input and a result into it, so without rewinding between calls the
    instance grows linearly with call count -- and a denied call in a retry
    loop is enough to exhaust it. SECURITY.md lists proxy DoS as in scope.
    """
    pol = OpaWasmPolicy(FIXTURE)
    call = {"tool": "spend", "arguments": {"amountCents": 500, "merchant": "acme"}}

    def pages() -> int:
        return pol._memory.size(pol._store)

    pol.query(call, ALLOW)  # one warm-up, so growth is measured at steady state
    before = pages()
    for _ in range(500):
        pol.query(call, ALLOW)

    assert pages() == before, (
        f"wasm heap grew {pages() - before} pages over 500 queries; the "
        "per-query opa_heap_ptr_set rewind is missing or ineffective"
    )

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Smoke tests for the common primitives: keys, did:key, JWS, VC envelopes."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from household_identity.common import did, jws, keys, vc


class TestKeys:
    def test_generate_keypair_returns_ed25519(self):
        key = keys.generate_keypair()
        assert isinstance(key, Ed25519PrivateKey)

    def test_public_bytes_is_32_bytes(self):
        key = keys.generate_keypair()
        assert len(keys.public_bytes(key)) == 32

    def test_private_bytes_is_32_bytes(self):
        key = keys.generate_keypair()
        assert len(keys.private_bytes(key)) == 32

    def test_private_jwk_roundtrip(self):
        key = keys.generate_keypair()
        jwk = keys.private_jwk(key)
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert "d" in jwk and "x" in jwk
        restored = keys.from_jwk(jwk)
        assert isinstance(restored, Ed25519PrivateKey)
        assert keys.private_bytes(restored) == keys.private_bytes(key)

    def test_public_jwk_has_no_d(self):
        key = keys.generate_keypair()
        pjwk = keys.public_jwk(key)
        assert "d" not in pjwk
        restored = keys.from_jwk(pjwk)
        assert isinstance(restored, Ed25519PublicKey)
        assert keys.public_bytes(restored) == keys.public_bytes(key)

    def test_save_and_load_private_jwk(self, tmp_path):
        key = keys.generate_keypair()
        path = tmp_path / "k.jwk"
        keys.save_private_jwk(key, path)
        loaded = keys.load_private_jwk(path)
        assert keys.private_bytes(loaded) == keys.private_bytes(key)

    def test_load_private_jwk_rejects_public_only(self, tmp_path):
        key = keys.generate_keypair()
        path = tmp_path / "pub.jwk"
        path.write_text(json.dumps(keys.public_jwk(key)))
        with pytest.raises(ValueError, match="not a private key"):
            keys.load_private_jwk(path)

    def test_from_jwk_rejects_wrong_curve(self):
        with pytest.raises(ValueError, match="Unsupported"):
            keys.from_jwk({"kty": "EC", "crv": "P-256", "x": "abc"})


class TestDidKey:
    def test_encode_decode_roundtrip(self):
        key = keys.generate_keypair()
        d = did.did_key_from_public_key(key)
        assert d.startswith("did:key:z")
        # canonical Ed25519 did:keys start with z6Mk
        assert d[len("did:key:"):].startswith("z6Mk")
        pub = did.did_key_to_public_bytes(d)
        assert pub == keys.public_bytes(key)

    def test_did_key_to_public_key_returns_object(self):
        key = keys.generate_keypair()
        d = did.did_key_from_public_key(key)
        recovered = did.did_key_to_public_key(d)
        assert isinstance(recovered, Ed25519PublicKey)
        assert keys.public_bytes(recovered) == keys.public_bytes(key)

    def test_decode_rejects_non_did_key(self):
        with pytest.raises(ValueError, match="not a base58btc-encoded did:key"):
            did.did_key_to_public_bytes("did:web:example.com")

    def test_known_vector(self):
        # Spec test vector from https://w3c-ccg.github.io/did-method-key/
        # "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp" → ed25519 pubkey
        # bytes 3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29
        did_str = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        expected = bytes.fromhex(
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
        )
        assert did.did_key_to_public_bytes(did_str) == expected


class TestJWS:
    def test_sign_and_verify_roundtrip(self):
        key = keys.generate_keypair()
        payload = {"hello": "world", "iss": "did:key:abc"}
        token = jws.sign_jwt(payload, key=key)
        assert token.count(".") == 2  # header.payload.signature
        decoded = jws.verify_jwt(token, key=key.public_key())
        assert decoded["hello"] == "world"
        assert decoded["iss"] == "did:key:abc"

    def test_verify_fails_with_wrong_key(self):
        signer = keys.generate_keypair()
        other = keys.generate_keypair()
        token = jws.sign_jwt({"x": 1}, key=signer)
        with pytest.raises(Exception):
            jws.verify_jwt(token, key=other.public_key())

    def test_kid_propagates_to_header(self):
        import base64

        key = keys.generate_keypair()
        token = jws.sign_jwt({"x": 1}, key=key, kid="did:key:abc#key-1")
        header_b64 = token.split(".")[0]
        # base64url decode with padding
        pad = "=" * (-len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64 + pad))
        assert header["alg"] == "Ed25519"
        assert header["kid"] == "did:key:abc#key-1"


class TestVCEnvelopes:
    def test_action_request_shape(self):
        payload = vc.make_action_request(
            issuer_did="did:key:abc",
            request_type="spend",
            details={"amount": 15.00, "currency": "USD"},
        )
        assert payload["iss"] == "did:key:abc"
        assert payload["jti"].startswith("urn:uuid:")
        assert "exp" in payload and "nbf" in payload
        assert payload["exp"] > payload["nbf"]
        types = payload["vc"]["type"]
        assert "VerifiableCredential" in types
        assert "ActionRequest" in types
        requests = payload["vc"]["credentialSubject"]["requests"]
        assert requests["type"] == "spend"
        assert requests["amount"] == 15.00

    def test_action_authorization_binds_to_request(self):
        # Build a request, sign it, hash the signed form, then build an auth.
        kid_key = keys.generate_keypair()
        parent_key = keys.generate_keypair()

        req_payload = vc.make_action_request(
            issuer_did="did:key:kid",
            request_type="spend",
            details={"amount": 15.00, "currency": "USD"},
        )
        signed_req = jws.sign_jwt(req_payload, key=kid_key)
        req_hash = vc.hash_request(signed_req)

        auth_payload = vc.make_action_authorization(
            issuer_did="did:key:parent",
            request_jti=req_payload["jti"],
            request_hash=req_hash,
            scope={"max_amount": 15.00, "currency": "USD"},
        )
        assert auth_payload["vc"]["credentialSubject"]["authorizes_request"] == req_payload["jti"]
        assert auth_payload["vc"]["credentialSubject"]["request_hash"] == req_hash
        assert auth_payload["vc"]["credentialSubject"]["scope"]["max_amount"] == 15.00

        signed_auth = jws.sign_jwt(auth_payload, key=parent_key)
        decoded = jws.verify_jwt(signed_auth, key=parent_key.public_key())
        assert decoded["vc"]["credentialSubject"]["request_hash"] == req_hash

    def test_hash_request_deterministic(self):
        signed = "header.payload.signature"
        h1 = vc.hash_request(signed)
        h2 = vc.hash_request(signed)
        assert h1 == h2
        assert h1.startswith("sha256:")

    def test_hash_request_distinguishes_different_inputs(self):
        assert vc.hash_request("a.b.c") != vc.hash_request("a.b.d")

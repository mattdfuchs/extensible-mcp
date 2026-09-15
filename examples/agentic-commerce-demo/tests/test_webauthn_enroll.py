# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Enrollment: recover the registered public key from a WebAuthn
attestationObject, without a browser. Builds the COSE key and attestationObject
the way `navigator.credentials.create()` would (minimal CBOR encoder here), then
checks the parser extracts a key that verifies a subsequent assertion."""

from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from extensible_mcp_vc.webauthn import (
    WebAuthnError,
    spend_challenge,
    b64url_encode,
    cose_ec2_to_public_key,
    parse_registration,
    verify_webauthn_assertion,
)

RP_ID = "approve.example"
ORIGIN = "https://approve.example"


# -- a tiny CBOR encoder, only for building test fixtures -------------------- #
def _head(major: int, n: int) -> bytes:
    mt = major << 5
    if n < 24:
        return bytes([mt | n])
    if n < 256:
        return bytes([mt | 24, n])
    if n < 65536:
        return bytes([mt | 25]) + n.to_bytes(2, "big")
    return bytes([mt | 26]) + n.to_bytes(4, "big")


def _cbor(x) -> bytes:
    if isinstance(x, int):
        return _head(0, x) if x >= 0 else _head(1, -1 - x)
    if isinstance(x, bytes):
        return _head(2, len(x)) + x
    if isinstance(x, str):
        b = x.encode()
        return _head(3, len(b)) + b
    if isinstance(x, dict):
        out = _head(5, len(x))
        for k, v in x.items():
            out += _cbor(k) + _cbor(v)
        return out
    raise TypeError(type(x))


def _cose_key(pub: ec.EllipticCurvePublicKey) -> bytes:
    n = pub.public_numbers()
    return _cbor(
        {1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}
    )


def _attestation_object(pub, cred_id: bytes) -> bytes:
    flags = 0x01 | 0x04 | 0x40  # UP | UV | AT
    auth_data = (
        hashlib.sha256(RP_ID.encode()).digest()
        + bytes([flags])
        + b"\x00\x00\x00\x01"  # signCount
        + b"\x00" * 16  # aaguid
        + len(cred_id).to_bytes(2, "big")
        + cred_id
        + _cose_key(pub)
    )
    return _cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})


def test_cose_ec2_key_roundtrips():
    key = ec.generate_private_key(ec.SECP256R1())
    recovered = cose_ec2_to_public_key(_cose_key(key.public_key()))
    assert recovered.public_numbers() == key.public_key().public_numbers()


def test_parse_registration_recovers_a_usable_key():
    key = ec.generate_private_key(ec.SECP256R1())
    cred_id = b"credential-abc-123"
    cred_id_out, pub = parse_registration(_attestation_object(key.public_key(), cred_id))
    assert cred_id_out == cred_id

    # the recovered key verifies an assertion the private key signs
    action = {"tool": "spend", "amountCents": 1500, "merchant": "acme"}
    client_data = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": b64url_encode(spend_challenge(action["tool"], action["amountCents"], action["merchant"])),
            "origin": ORIGIN,
        }
    ).encode()
    auth = hashlib.sha256(RP_ID.encode()).digest() + bytes([0x05]) + b"\x00\x00\x00\x02"
    sig = key.sign(
        auth + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
    )
    verify_webauthn_assertion(
        public_key=pub,
        authenticator_data=auth,
        client_data_json=client_data,
        signature=sig,
        expected_challenge=spend_challenge(action["tool"], action["amountCents"], action["merchant"]),
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
    )


def test_non_ec2_cose_key_rejected():
    with pytest.raises(WebAuthnError, match="EC2"):
        cose_ec2_to_public_key(_cbor({1: 1}))  # kty=1 (OKP), not EC2


def test_attestation_without_authdata_rejected():
    with pytest.raises(WebAuthnError, match="authData"):
        parse_registration(_cbor({"fmt": "none", "attStmt": {}}))

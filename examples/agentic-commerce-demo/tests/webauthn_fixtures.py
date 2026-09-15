# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Headless WebAuthn fixtures: a minimal CBOR encoder plus builders for the two
artifacts a browser authenticator would produce — a registration
``attestationObject`` (an ES256/P-256 COSE key) and a ``navigator.credentials.get``
assertion signing over a server-set challenge. Shared by the approval-service,
purchase, and negotiation tests so the assertion-forging logic lives in one place.

Not a test module (no ``test_`` prefix), so pytest imports but does not collect it.
"""

from __future__ import annotations

import hashlib
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from extensible_mcp_vc.webauthn import b64url_encode

# The FastAPI TestClient serves from http://testserver, so the rpId/origin the
# server derives from the request match these.
RP_ID = "testserver"
ORIGIN = "http://testserver"


def _head(major, n):
    mt = major << 5
    return bytes([mt | n]) if n < 24 else bytes([mt | 24, n]) if n < 256 else bytes([mt | 25]) + n.to_bytes(2, "big")


def _cbor(x):
    if isinstance(x, int):
        return _head(0, x) if x >= 0 else _head(1, -1 - x)
    if isinstance(x, bytes):
        return _head(2, len(x)) + x
    if isinstance(x, str):
        b = x.encode(); return _head(3, len(b)) + b
    if isinstance(x, dict):
        out = _head(5, len(x))
        for k, v in x.items():
            out += _cbor(k) + _cbor(v)
        return out
    raise TypeError


def attestation_object(pub, cred_id: bytes) -> bytes:
    """A ``fmt: none`` attestation object embedding ``pub`` as an ES256 COSE key —
    what ``navigator.credentials.create`` hands back at enrollment."""
    n = pub.public_numbers()
    cose = _cbor({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})
    auth = (hashlib.sha256(RP_ID.encode()).digest() + bytes([0x01 | 0x04 | 0x40])
            + b"\x00\x00\x00\x01" + b"\x00" * 16 + len(cred_id).to_bytes(2, "big") + cred_id + cose)
    return _cbor({"fmt": "none", "attStmt": {}, "authData": auth})


def assertion_for(key, challenge: bytes, *, flags: int = 0x05) -> dict[str, str]:
    """A WebAuthn assertion signing over an arbitrary server-set ``challenge``
    (bytes). ``flags`` defaults to UP|UV; pass ``0x01`` for present-not-verified."""
    client = json.dumps(
        {"type": "webauthn.get", "challenge": b64url_encode(challenge), "origin": ORIGIN}
    ).encode()
    auth = hashlib.sha256(RP_ID.encode()).digest() + bytes([flags]) + b"\x00\x00\x00\x02"
    sig = key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
    return {
        "authenticatorData": b64url_encode(auth),
        "clientDataJSON": b64url_encode(client),
        "signature": b64url_encode(sig),
    }

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Shared test primitives: Ed25519 signing matching the identity layer.

Not collected by pytest (no ``test_`` prefix). Signs with the curve-specific
``Ed25519`` JOSE alg — the same one household-identity uses — so tests exercise
real credential interop against the compiled ``family_spend``-family policies.
"""

from __future__ import annotations

import json
from typing import Any

TRUST_DID = "did:key:trust"
KID_DID = "did:key:kid"
PARENT_DID = "did:key:parent"

_VALID_WINDOW = {"nbf": 0, "exp": 9999999999}


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def new_key():
    from joserfc.jwk import OKPKey

    return OKPKey.generate_key("Ed25519")


def _b58encode(b: bytes) -> str:
    num = int.from_bytes(b, "big")
    out = ""
    while num > 0:
        num, rem = divmod(num, 58)
        out = _B58[rem] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + out


def did_key(key) -> str:
    """The ``did:key`` for an Ed25519 public key (multicodec 0xed01 + base58btc)."""
    import base64

    x = key.as_dict(private=False)["x"]
    pub = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    return "did:key:z" + _b58encode(b"\xed\x01" + pub)


def public_jwk(key) -> str:
    return json.dumps(key.as_dict(private=False))


def sign(payload: dict, key) -> str:
    from joserfc import jws

    return jws.serialize_compact(
        {"alg": "Ed25519"}, json.dumps(payload).encode(), key, algorithms=["Ed25519"]
    )


def membership(*, sub: str, role: str, key, iss: str = TRUST_DID) -> dict:
    return {
        "jws": sign({"sub": sub}, key),
        "claims": {"iss": iss, "sub": sub, "role": role, **_VALID_WINDOW},
    }


def request_vc(*, args: dict[str, Any], key, iss: str = KID_DID, jti: str = "r1") -> dict:
    return {
        "jws": sign({"sub": iss}, key),
        "claims": {"jti": jti, "iss": iss, "action": "send", "arguments": args, **_VALID_WINDOW},
    }


def authorization_vc(*, request_jws: str, key, iss: str = PARENT_DID, jti: str = "r1") -> dict:
    import hashlib

    return {
        "jws": sign({"sub": iss}, key),
        "claims": {
            "jti": jti,
            "iss": iss,
            "requestHash": hashlib.sha256(request_jws.encode()).hexdigest(),
            **_VALID_WINDOW,
        },
    }

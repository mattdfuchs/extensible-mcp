# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""JWS sign and verify primitives for JWT-shaped VCs, using Ed25519 keys.

Uses the RFC 9864 curve-specific algorithm name ``Ed25519`` rather than the
older RFC 8037 ``EdDSA`` identifier. The cryptography is the same; the JOSE
algorithm header is the modern form. This is a closed-network system today,
so we can adopt the modern identifier without interop concerns.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from joserfc import jwt
from joserfc.jwk import OKPKey

from .keys import private_jwk, public_jwk

ALG = "Ed25519"


def sign_jwt(
    payload: dict[str, Any],
    *,
    key: Ed25519PrivateKey,
    kid: str | None = None,
) -> str:
    """Sign a JWT payload with an Ed25519 private key. Returns the compact JWS string."""
    header: dict[str, Any] = {"alg": ALG, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    okp = OKPKey.import_key(private_jwk(key))
    return jwt.encode(header, payload, okp, algorithms=[ALG])


def verify_jwt(
    token: str,
    *,
    key: Ed25519PublicKey,
) -> dict[str, Any]:
    """Verify a JWT signature with an Ed25519 public key. Returns the decoded claims.

    Raises joserfc.errors.BadSignatureError (or similar) on signature mismatch.
    Does NOT validate exp/nbf — temporal validation is a separate concern.
    """
    okp = OKPKey.import_key(public_jwk(key))
    decoded = jwt.decode(token, okp, algorithms=[ALG])
    return dict(decoded.claims)

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Ed25519 keypair generation, JWK serialization, and on-disk persistence."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def generate_keypair() -> Ed25519PrivateKey:
    """Generate a fresh Ed25519 keypair."""
    return Ed25519PrivateKey.generate()


def public_bytes(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    """Return the raw 32-byte public key for an Ed25519 key."""
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def private_bytes(key: Ed25519PrivateKey) -> bytes:
    """Return the raw 32-byte private seed for an Ed25519 private key."""
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def private_jwk(key: Ed25519PrivateKey) -> dict:
    """Return the full (private + public) JWK as a plain dict."""
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "d": _b64url(private_bytes(key)),
        "x": _b64url(public_bytes(key)),
    }


def public_jwk(key: Ed25519PrivateKey | Ed25519PublicKey) -> dict:
    """Return the public-only JWK as a plain dict."""
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(public_bytes(key)),
    }


def from_jwk(jwk: dict) -> Ed25519PrivateKey | Ed25519PublicKey:
    """Load an Ed25519 key from a JWK dict. Private if 'd' is present, else public."""
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError(
            f"Unsupported key type: kty={jwk.get('kty')}, crv={jwk.get('crv')}"
        )
    if "d" in jwk:
        return Ed25519PrivateKey.from_private_bytes(_b64url_decode(jwk["d"]))
    return Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))


def save_private_jwk(key: Ed25519PrivateKey, path: Path) -> None:
    """Write a private JWK to a file with 0600 permissions where supported."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(private_jwk(key), indent=2))
    try:
        path.chmod(0o600)
    except (OSError, NotImplementedError):
        pass  # best-effort; Windows / unusual filesystems may not support


def load_private_jwk(path: Path) -> Ed25519PrivateKey:
    """Load a private Ed25519 key from a JWK file."""
    jwk = json.loads(path.read_text())
    if "d" not in jwk:
        raise ValueError(f"JWK at {path} is not a private key (no 'd' component)")
    key = from_jwk(jwk)
    assert isinstance(key, Ed25519PrivateKey)
    return key

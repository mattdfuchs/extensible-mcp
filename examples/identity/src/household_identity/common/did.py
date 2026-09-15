# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""did:key encoding and decoding for Ed25519 public keys.

did:key spec: https://w3c-ccg.github.io/did-method-key/

Format for Ed25519: did:key:z<base58btc>(0xED 0x01 || pubkey-bytes-32)
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .keys import public_bytes

# Multicodec varint for ed25519-pub: 0xED encodes as 0xED 0x01 in varint form.
ED25519_MULTICODEC_PREFIX = b"\xed\x01"

# Base58btc alphabet (Bitcoin variant)
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_B58_ALPHABET[r])
    # Preserve leading zero bytes as leading '1' characters
    for byte in data:
        if byte == 0:
            out.append(_B58_ALPHABET[0])
        else:
            break
    return bytes(reversed(out)).decode("ascii")


def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        idx = _B58_ALPHABET.find(ch.encode("ascii"))
        if idx < 0:
            raise ValueError(f"invalid base58 character: {ch!r}")
        n = n * 58 + idx
    out = n.to_bytes((n.bit_length() + 7) // 8, "big")
    # Preserve leading '1' characters as leading zero bytes
    leading_zeros = len(s) - len(s.lstrip("1"))
    return b"\x00" * leading_zeros + out


def did_key_from_public_key(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    """Encode an Ed25519 public key as a did:key string."""
    pub = public_bytes(key)
    payload = ED25519_MULTICODEC_PREFIX + pub
    return f"did:key:z{_b58encode(payload)}"


def did_key_to_public_bytes(did: str) -> bytes:
    """Decode a did:key string to the raw 32-byte Ed25519 public key."""
    if not did.startswith("did:key:z"):
        raise ValueError(f"not a base58btc-encoded did:key: {did!r}")
    encoded = did.removeprefix("did:key:z")
    payload = _b58decode(encoded)
    if not payload.startswith(ED25519_MULTICODEC_PREFIX):
        raise ValueError(
            f"did:key has unsupported multicodec prefix "
            f"(expected ed25519-pub 0xED 0x01); got: {payload[:2].hex()}"
        )
    pub = payload[len(ED25519_MULTICODEC_PREFIX):]
    if len(pub) != 32:
        raise ValueError(
            f"Ed25519 public key must be 32 bytes; got {len(pub)} bytes"
        )
    return pub


def did_key_to_public_key(did: str) -> Ed25519PublicKey:
    """Decode a did:key string to an Ed25519PublicKey object."""
    return Ed25519PublicKey.from_public_bytes(did_key_to_public_bytes(did))

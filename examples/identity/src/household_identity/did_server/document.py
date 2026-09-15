# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Build a W3C DID document for a did:web admin identity."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..common import keys

DID_CONTEXT = ["https://www.w3.org/ns/did/v1"]


def make_did_document(
    *,
    did: str,
    key: Ed25519PrivateKey | Ed25519PublicKey,
    key_id_suffix: str = "key-1",
) -> dict[str, Any]:
    """Build a DID document for ``did`` with one Ed25519 verification method.

    The verification method id is ``{did}#{key_id_suffix}`` and is referenced
    from both ``assertionMethod`` and ``authentication`` so it can sign VCs
    and answer authentication challenges.
    """
    vm_id = f"{did}#{key_id_suffix}"
    return {
        "@context": list(DID_CONTEXT),
        "id": did,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": keys.public_jwk(key),
            }
        ],
        "assertionMethod": [vm_id],
        "authentication": [vm_id],
    }

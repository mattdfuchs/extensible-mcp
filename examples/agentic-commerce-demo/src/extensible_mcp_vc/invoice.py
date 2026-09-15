# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Merchant-signed invoice — the buyer binds consent and payment to the
*merchant's* cryptographic commitment to the terms, not to the buyer agent's
account of a negotiation.

Stage 1 of the agentic-commerce loop (the A2A / signed-invoice flow): a merchant
(the pizza place) issues an invoice signed with its own key; the buyer verifies
it against a **closed trusted-merchant set** — the buyer-side mirror of the
trusted-admin set used for the humans' memberships; the kid/parent WebAuthn
approvals then bind to the *invoice hash*; and payment executes the invoice's
total to its merchant.

Why the signed invoice is the linchpin: the buyer agent negotiates over A2A with
an *untrusted* counterparty agent, so it may itself be steered by that chat.
Nothing may bind until there is a signed invoice — the humans approve, and the
policy pays, exactly what the merchant committed to, verified independently of
any LLM's summary. Expiry + nonce prevent replay. This is AP2's Cart Mandate in
miniature.

The invoice is signed with the merchant's **Ed25519** key (a did:key-style
merchant identity), matching the credential world; the humans still approve via
WebAuthn (P-256) — two parties, two mechanisms.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .webauthn import b64url_decode, b64url_encode


class InvoiceError(Exception):
    """An invoice failed verification (bad signature / untrusted merchant / expired)."""


def canonical_invoice(invoice: dict[str, Any]) -> bytes:
    """Canonical bytes of an invoice — sorted-key, separatorless JSON, so the
    merchant's signature and the buyer's recomputed hash agree byte-for-byte."""
    return json.dumps(invoice, sort_keys=True, separators=(",", ":")).encode()


def sign_invoice(invoice: dict[str, Any], merchant_key: Ed25519PrivateKey) -> str:
    """The merchant signs its invoice; returns a base64url Ed25519 signature."""
    return b64url_encode(merchant_key.sign(canonical_invoice(invoice)))


def invoice_challenge(invoice: dict[str, Any]) -> bytes:
    """The WebAuthn challenge the humans' approvals bind to: the hex-ASCII of the
    invoice hash (matching the challenge form, so it drops straight into
    ``verify_webauthn_assertion``). Approving *this* challenge is approving
    *this* invoice, and no other."""
    return hashlib.sha256(canonical_invoice(invoice)).hexdigest().encode()


def verify_invoice(
    invoice: dict[str, Any],
    signature: str,
    *,
    trusted_merchants: dict[str, Ed25519PublicKey],
    now: int | None = None,
) -> None:
    """Raise :class:`InvoiceError` unless the invoice is signed by a **trusted**
    merchant and is unexpired.

    ``trusted_merchants`` maps ``merchantId`` to the merchant's Ed25519 public
    key — the closed set the buyer will transact with. An invoice from an
    unknown merchant is refused *before* any signature check, so a
    prompt-injected counterparty cannot steer a purchase to a merchant the buyer
    never trusted.
    """
    merchant_id = invoice.get("merchantId")
    key = trusted_merchants.get(merchant_id)
    if key is None:
        raise InvoiceError(f"merchant {merchant_id!r} is not in the trusted set")
    try:
        key.verify(b64url_decode(signature), canonical_invoice(invoice))
    except InvalidSignature as e:
        raise InvoiceError("invoice signature does not verify") from e
    exp = invoice.get("exp")
    if exp is not None:
        when = now if now is not None else int(time.time())
        if when >= exp:
            raise InvoiceError("invoice has expired")


def public_key_from_raw(raw_b64url: str) -> Ed25519PublicKey:
    """An Ed25519 public key from its base64url raw (32-byte) encoding — how a
    merchant's key is registered into the trusted set."""
    return Ed25519PublicKey.from_public_bytes(b64url_decode(raw_b64url))

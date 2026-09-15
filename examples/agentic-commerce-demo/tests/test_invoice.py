# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Merchant-signed invoice: sign, verify against a trusted-merchant set, and the
invoice→challenge binding. A tampered invoice, an untrusted merchant, or an
expired invoice must all be refused."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from extensible_mcp_vc.invoice import (
    InvoiceError,
    invoice_challenge,
    public_key_from_raw,
    sign_invoice,
    verify_invoice,
)
from extensible_mcp_vc.webauthn import b64url_encode

NOW = 1_000_000


def _invoice(**over):
    inv = {
        "merchantId": "pizza-1",
        "merchant": "Tony's Pizza",
        "items": [{"name": "Large Pepperoni", "qty": 1}],
        "totalCents": 1800,
        "currency": "usd",
        "exp": NOW + 600,
        "nonce": "urn:uuid:inv-1",
    }
    inv.update(over)
    return inv


def _merchant():
    key = Ed25519PrivateKey.generate()
    raw = b64url_encode(key.public_key().public_bytes_raw())
    return key, {"pizza-1": public_key_from_raw(raw)}


def test_valid_invoice_verifies():
    key, trusted = _merchant()
    inv = _invoice()
    verify_invoice(inv, sign_invoice(inv, key), trusted_merchants=trusted, now=NOW)


def test_tampered_invoice_rejected():
    key, trusted = _merchant()
    inv = _invoice()
    sig = sign_invoice(inv, key)
    inv["totalCents"] = 50_000  # change the price after signing
    with pytest.raises(InvoiceError, match="signature"):
        verify_invoice(inv, sig, trusted_merchants=trusted, now=NOW)


def test_untrusted_merchant_rejected():
    key, _ = _merchant()
    inv = _invoice(merchantId="not-trusted")
    with pytest.raises(InvoiceError, match="not in the trusted set"):
        verify_invoice(inv, sign_invoice(inv, key), trusted_merchants={}, now=NOW)


def test_wrong_merchant_key_rejected():
    key, trusted = _merchant()
    other = Ed25519PrivateKey.generate()  # a different key signs
    inv = _invoice()
    with pytest.raises(InvoiceError, match="signature"):
        verify_invoice(inv, sign_invoice(inv, other), trusted_merchants=trusted, now=NOW)


def test_expired_invoice_rejected():
    key, trusted = _merchant()
    inv = _invoice(exp=NOW - 1)
    with pytest.raises(InvoiceError, match="expired"):
        verify_invoice(inv, sign_invoice(inv, key), trusted_merchants=trusted, now=NOW)


def test_invoice_challenge_is_stable_and_specific():
    a, b = _invoice(), _invoice(totalCents=1900)
    assert invoice_challenge(a) == invoice_challenge(_invoice())  # same invoice -> same
    assert invoice_challenge(a) != invoice_challenge(b)  # any change -> different

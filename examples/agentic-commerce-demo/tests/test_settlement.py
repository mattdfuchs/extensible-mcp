# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Settlement: charge an approved invoice on a (mock) rail and mint a signed
receipt; verify that receipt against the invoice it settles. A forged receipt, a
receipt for a different order, a declined charge, or a tampered amount must all
be refused — the merchant fulfils only against a receipt that verifies."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from extensible_mcp_vc.settlement import (
    MockExecutor,
    PaymentDeclined,
    SettlementError,
    settle,
    verify_receipt,
)


def _invoice(**over):
    inv = {
        "merchantId": "pizza-1",
        "merchant": "Tony's Pizza",
        "items": [{"name": "Large Pepperoni", "qty": 1}],
        "totalCents": 1800,
        "currency": "usd",
        "exp": 4_000_000_000,
        "nonce": "urn:uuid:inv-1",
    }
    inv.update(over)
    return inv


def _rail():
    return Ed25519PrivateKey.generate()


def test_settle_produces_a_verifiable_receipt():
    key = _rail()
    inv = _invoice()
    receipt, sig = settle(inv, executor=MockExecutor(), settlement_key=key)
    assert receipt["amountCents"] == 1800 and receipt["status"] == "succeeded"
    # the merchant's check, against the invoice it issued, passes
    verify_receipt(receipt, sig, settlement_key_pub=key.public_key(), invoice=inv)


def test_receipt_is_idempotent_in_the_nonce():
    key = _rail()
    inv = _invoice()
    r1, _ = settle(inv, executor=MockExecutor(), settlement_key=key)
    r2, _ = settle(inv, executor=MockExecutor(), settlement_key=key)
    assert r1["paymentRef"] == r2["paymentRef"]  # same nonce -> same rail reference


def test_forged_receipt_rejected():
    key, imposter = _rail(), _rail()
    inv = _invoice()
    receipt, _ = settle(inv, executor=MockExecutor(), settlement_key=key)
    forged_sig = settle(inv, executor=MockExecutor(), settlement_key=imposter)[1]
    with pytest.raises(SettlementError, match="signature"):
        verify_receipt(receipt, forged_sig, settlement_key_pub=key.public_key(), invoice=inv)


def test_receipt_for_a_different_order_rejected():
    key = _rail()
    paid = _invoice()
    receipt, sig = settle(paid, executor=MockExecutor(), settlement_key=key)
    other = _invoice(totalCents=100, nonce="urn:uuid:other")
    with pytest.raises(SettlementError, match="does not match"):
        verify_receipt(receipt, sig, settlement_key_pub=key.public_key(), invoice=other)


def test_tampered_amount_rejected():
    key = _rail()
    inv = _invoice()
    receipt, sig = settle(inv, executor=MockExecutor(), settlement_key=key)
    receipt["amountCents"] = 1  # cheapen the receipt after signing
    with pytest.raises(SettlementError, match="signature"):
        verify_receipt(receipt, sig, settlement_key_pub=key.public_key(), invoice=inv)


def test_declined_charge_yields_no_receipt():
    key = _rail()
    with pytest.raises(PaymentDeclined):
        settle(_invoice(), executor=MockExecutor(decline=True), settlement_key=key)

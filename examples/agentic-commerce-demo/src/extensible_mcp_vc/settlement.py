# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Settlement — execute an approved invoice on a payment rail and mint a
**signed payment receipt**.

Stage 3 of the agentic-commerce loop. The party that verified the human consent
(the approval service) is the one that executes: once the required humans have
approved an invoice, it charges the rail for *exactly the invoice's terms* and
signs a receipt over ``{nonce, merchantId, amountCents, currency, paymentRef,
status}``. That receipt is the fulfilment evidence — the merchant verifies the
rail's signature and matches it against the invoice it issued, so it never
fulfils on the buyer agent's word.

Two properties carry through from the earlier stages:

- **The terms are the invoice's, not a re-supplied number.** The amount and
  merchant come straight off the approved invoice; nothing downstream (least of
  all an LLM) reintroduces them.
- **The nonce is the idempotency key.** A retry charges the rail at most once
  (Stripe's ``idempotency_key``) and the merchant fulfils at most once, so a
  replayed approval can neither double-charge nor double-ship.

The rail credential lives here, server-side; the receipt it emits is public
signed evidence, safe to hand to the buyer to relay to the merchant.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Callable, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .webauthn import b64url_decode, b64url_encode


class SettlementError(Exception):
    """A payment receipt failed verification (bad signature / wrong terms)."""


class PaymentDeclined(Exception):
    """The rail did not complete the charge (declined, error, non-final status)."""


# An executor takes an invoice and returns ``(payment_ref, status)``; it must
# raise :class:`PaymentDeclined` rather than return a non-success status.
Executor = Callable[[dict[str, Any]], "tuple[str, str]"]


def payment_receipt(invoice: dict[str, Any], payment_ref: str, status: str) -> dict[str, Any]:
    """The receipt fields, lifted straight from the invoice plus the rail's
    reference — so the receipt commits to the same terms the humans approved."""
    return {
        "nonce": invoice["nonce"],
        "merchantId": invoice["merchantId"],
        "amountCents": invoice["totalCents"],
        "currency": invoice["currency"],
        "paymentRef": payment_ref,
        "status": status,
    }


def canonical_receipt(receipt: dict[str, Any]) -> bytes:
    """Canonical bytes of a receipt — sorted-key, separatorless JSON, so the
    rail's signature and the merchant's recomputed check agree byte-for-byte."""
    return json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()


def sign_receipt(receipt: dict[str, Any], settlement_key: Ed25519PrivateKey) -> str:
    """The settlement authority signs a receipt; returns a base64url signature."""
    return b64url_encode(settlement_key.sign(canonical_receipt(receipt)))


def settle(
    invoice: dict[str, Any],
    *,
    executor: Executor,
    settlement_key: Ed25519PrivateKey,
) -> tuple[dict[str, Any], str]:
    """Charge the rail for the invoice's terms and return ``(receipt, signature)``.

    Raises :class:`PaymentDeclined` if the rail did not succeed; in that case no
    receipt is produced, so the merchant is never handed evidence of a payment
    that did not clear.
    """
    payment_ref, status = executor(invoice)
    if status != "succeeded":
        raise PaymentDeclined(f"rail returned status {status!r} for {invoice['nonce']}")
    receipt = payment_receipt(invoice, payment_ref, status)
    return receipt, sign_receipt(receipt, settlement_key)


def verify_receipt(
    receipt: dict[str, Any],
    signature: str,
    *,
    settlement_key_pub: Ed25519PublicKey,
    invoice: dict[str, Any],
) -> None:
    """Raise :class:`SettlementError` unless ``receipt`` is signed by the trusted
    settlement authority, settles *this* ``invoice``, and reports success.

    The merchant calls this against the invoice it recorded at quote time, so a
    valid receipt for a *different* order cannot fulfil this one.
    """
    try:
        settlement_key_pub.verify(b64url_decode(signature), canonical_receipt(receipt))
    except InvalidSignature as e:
        raise SettlementError("receipt signature does not verify") from e
    if receipt.get("status") != "succeeded":
        raise SettlementError(f"receipt status is {receipt.get('status')!r}, not succeeded")
    for field, want in (
        ("nonce", invoice["nonce"]),
        ("merchantId", invoice["merchantId"]),
        ("amountCents", invoice["totalCents"]),
        ("currency", invoice["currency"]),
    ):
        if receipt.get(field) != want:
            raise SettlementError(
                f"receipt {field}={receipt.get(field)!r} does not match the order ({want!r})"
            )


class MockExecutor:
    """An in-memory rail for tests and the no-Stripe demo. Deterministic: the
    payment reference is derived from the invoice nonce (no clock / randomness),
    so a retry with the same nonce yields the same reference — idempotent."""

    def __init__(self, *, decline: bool = False) -> None:
        self._decline = decline

    def __call__(self, invoice: dict[str, Any]) -> tuple[str, str]:
        if self._decline:
            return ("", "declined")
        tail = hashlib.sha256(invoice["nonce"].encode()).hexdigest()[:16]
        return (f"mock_pi_{tail}", "succeeded")


class StripeExecutor:
    """A real test-mode Stripe charge. The invoice ``nonce`` is the idempotency
    key, so a replay cannot double-charge; refuses non-test keys, exactly like
    ``stripe_spend_server``. The card credential lives here, server-side."""

    def __init__(self) -> None:
        key = os.environ.get("STRIPE_API_KEY", "")
        if not key:
            raise RuntimeError("STRIPE_API_KEY is not set (use a sk_test_… key)")
        if not key.startswith("sk_test_"):
            raise RuntimeError("refusing to run against a non-test Stripe key")
        try:
            import stripe
        except ImportError as e:  # pragma: no cover - environment
            raise RuntimeError("stripe is not installed. Run: uv sync --extra stripe") from e
        stripe.api_key = key
        self._stripe = stripe

    def __call__(self, invoice: dict[str, Any]) -> tuple[str, str]:
        intent = self._stripe.PaymentIntent.create(
            amount=int(invoice["totalCents"]),
            currency=invoice["currency"],
            payment_method="pm_card_visa",
            payment_method_types=["card"],
            confirm=True,
            description=f"invoice {invoice['nonce']} at {invoice['merchantId']}",
            metadata={"nonce": invoice["nonce"], "merchantId": invoice["merchantId"]},
            idempotency_key=invoice["nonce"],  # the signed invoice's nonce, not a fresh uuid
        )
        return (intent.id, intent.status)


def executor_from_env() -> Executor:
    """Pick the rail from ``SETTLEMENT`` (``mock`` default, ``stripe`` for real)."""
    choice = os.environ.get("SETTLEMENT", "mock")
    if choice == "stripe":
        return StripeExecutor()
    return MockExecutor()

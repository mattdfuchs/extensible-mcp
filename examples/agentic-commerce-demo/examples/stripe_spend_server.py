# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Stripe-backed execution rail — a real downstream for the policy-bundle demo.

A drop-in replacement for the mock ``demo_spend_server`` (same ``spend(amount,
merchant)`` tool), except it actually moves money via Stripe instead of
debiting an in-memory balance. The proxy in front gates ``spend`` behind the
supplied VC / WebAuthn policy bundle exactly as before — the bundle governs this
server unchanged; only the execution leg is now the payment rail.

The card never enters the LLM's context: the Stripe secret key lives here,
server-side, and the tool traffics in a **test PaymentMethod handle**
(``pm_card_visa``), not card numbers — which keeps this in Stripe's light PCI
tier. The LLM can *initiate* a charge; it can neither see nor exfiltrate the
credential, and the policy has already bound the amount/merchant to signed
human consent before the call ever reaches here.

Setup (test mode only):

    uv sync --extra stripe           # installs the optional `stripe` dependency
    export STRIPE_API_KEY=sk_test_…  # a *test* key; this refuses live keys

Then start the proxy with ``DOWNSTREAM=stripe`` and it routes here instead of
the mock ``demo_spend_server``:

    DOWNSTREAM=stripe STRIPE_API_KEY=sk_test_… uv run python examples/family_proxy_server.py
"""

from __future__ import annotations

import logging
import os
import uuid

from fastmcp import FastMCP

logger = logging.getLogger("stripe_spend_server")
server = FastMCP(name="payments")


def _stripe():
    """Lazily import + configure Stripe, failing loudly (never silently)."""
    try:
        import stripe
    except ImportError as e:  # pragma: no cover - environment
        raise RuntimeError(
            "stripe is not installed. Run: uv sync --extra stripe"
        ) from e
    key = os.environ.get("STRIPE_API_KEY", "")
    if not key:
        raise RuntimeError("STRIPE_API_KEY is not set (use a sk_test_… key)")
    if not key.startswith("sk_test_"):
        raise RuntimeError("refusing to run against a non-test Stripe key")
    stripe.api_key = key
    return stripe


@server.tool(
    name="spend",
    description=(
        "Spend `amount` dollars at `merchant`. Executes a real card charge via "
        "Stripe (test mode) and returns a confirmation with the charge id."
    ),
)
async def spend(amount: float, merchant: str, currency: str = "usd") -> str:
    stripe = _stripe()
    amount_cents = int(round(amount * 100))
    try:
        intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency=currency,
            payment_method="pm_card_visa",  # Stripe shared test PaymentMethod
            payment_method_types=["card"],
            confirm=True,
            description=f"agent-initiated charge at {merchant}",
            metadata={"merchant": merchant},
            # A per-call uuid, deliberately. Deriving the key from the signed
            # request is impossible here and would be the wrong layer anyway:
            # the proxy strips the credentials before forwarding, so this
            # server never sees the evidence that authorized it. Replay is
            # refused upstream instead, by SingleUseEvidenceFilter keying on
            # the request VC's jti -- which is inside what the human signed,
            # so the LLM cannot vary it. A fresh key here only means a genuine
            # network retry of one authorized charge is not deduplicated by
            # Stripe; the authorization itself is already single-use.
            idempotency_key=str(uuid.uuid4()),
        )
    except Exception as e:  # noqa: BLE001 - surface the rail's error to the caller
        logger.warning("[STRIPE] charge failed ($%.2f at %s): %s", amount, merchant, e)
        return f"charge failed: {e}"
    logger.info(
        "[STRIPE] PaymentIntent %s: %s ($%.2f %s at %s)",
        intent.id, intent.status, amount, currency.upper(), merchant,
    )
    return (
        f"OK. Charged ${amount:.2f} {currency.upper()} at {merchant}. "
        f"PaymentIntent {intent.id}: {intent.status}."
    )


if __name__ == "__main__":
    server.run()

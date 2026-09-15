# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Isolate the Stripe test-mode charge from the whole proxy / policy / wallet
stack. Given a test key, it creates and confirms one $5 PaymentIntent and prints
the result (or the exact Stripe error) — so you can tell whether the *Stripe
integration itself* works, independent of enforcement.

    uv sync --extra stripe
    STRIPE_API_KEY=sk_test_… uv run python examples/stripe_smoke.py

If this prints a PaymentIntent id with status "succeeded", the rail works and it
will appear in the Stripe Dashboard → **Payments** (Test-mode toggle ON — *not*
the Balance view). If it errors, the message is the exact fix needed.
"""

from __future__ import annotations

import os
import sys
import uuid


def main() -> None:
    try:
        import stripe
    except ImportError:
        sys.exit("stripe not installed — run: uv sync --extra stripe")

    key = os.environ.get("STRIPE_API_KEY", "")
    if not key.startswith("sk_test_"):
        sys.exit("set STRIPE_API_KEY to a sk_test_… (test) key")
    stripe.api_key = key

    print("creating a $5.00 test PaymentIntent (pm_card_visa)…")
    try:
        intent = stripe.PaymentIntent.create(
            amount=500,
            currency="usd",
            payment_method="pm_card_visa",
            payment_method_types=["card"],
            confirm=True,
            description="stripe smoke test",
            idempotency_key=str(uuid.uuid4()),
        )
    except Exception as e:  # noqa: BLE001 - we want the raw Stripe error text
        print(f"\nERROR from Stripe: {type(e).__name__}: {e}")
        print("Paste this to get a one-line fix to the create() call.")
        sys.exit(1)

    print(f"\nPaymentIntent: {intent.id}")
    print(f"status:        {intent.status}")
    print(f"amount:        {intent.amount} {intent.currency}")
    print(
        f"\nLook in the Stripe Dashboard → Payments (Test mode ON) for {intent.id}. "
        f"Status 'succeeded' means the rail works."
    )


if __name__ == "__main__":
    main()

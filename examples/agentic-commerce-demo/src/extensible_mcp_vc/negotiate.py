# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Buyer-side A2A negotiation — the family agent's side of talking to a merchant.

The family agent discovers the merchant (its card + menu) and places an order,
receiving a merchant-signed invoice in return. This is the untrusted leg: the
counterparty is a foreign agent the buyer does not control. So the buyer treats
*nothing* here as authoritative on the counterparty's word — it re-verifies the
returned invoice against its own trusted-merchant set before the invoice is ever
shown to a human. A manipulated or hostile counterparty (or a manipulated buyer
agent relaying it) can, at worst, fail to produce a valid invoice; it cannot
forge terms the humans will then approve.

The transport is injected (any ``httpx.Client``-compatible object with ``get`` /
``post``), so this drives both a real network merchant and a FastAPI
``TestClient`` unchanged.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .invoice import verify_invoice


class NegotiationError(Exception):
    """The A2A negotiation did not yield an acceptable signed invoice."""


def fetch_merchant_card(client) -> dict[str, Any]:
    """Discover the counterparty: its id, name, and the public key the buyer must
    have in its trusted set to accept this merchant's invoices."""
    r = client.get("/merchant-card")
    r.raise_for_status()
    return r.json()


def fetch_menu(client) -> list[dict[str, Any]]:
    r = client.get("/menu")
    r.raise_for_status()
    return r.json()["items"]


def negotiate_order(
    client,
    items: list[dict[str, Any]],
    *,
    trusted_merchants: dict[str, Ed25519PublicKey] | None = None,
) -> tuple[dict[str, Any], str]:
    """Place ``items`` (``[{"name", "qty"}]``) with the merchant agent and return
    the ``(invoice, signature)`` it signs.

    If ``trusted_merchants`` is given, the invoice is verified against it here —
    at the agent boundary — so a garbled or rogue response is caught before it
    travels any further. This is advisory defense-in-depth: the approval service
    re-verifies authoritatively before any human sees it.
    """
    r = client.post("/quote", json={"items": items})
    if r.status_code != 200:
        raise NegotiationError(f"merchant refused the order ({r.status_code}): {r.text}")
    body = r.json()
    invoice, signature = body["invoice"], body["signature"]
    if trusted_merchants is not None:
        # verify_invoice raises InvoiceError on an untrusted/tampered/expired
        # invoice; surface it as a negotiation failure.
        try:
            verify_invoice(invoice, signature, trusted_merchants=trusted_merchants)
        except Exception as e:  # noqa: BLE001 - re-wrap invoice errors uniformly
            raise NegotiationError(f"merchant invoice did not verify: {e}") from e
    return invoice, signature

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The merchant agent — the pizza place — the *untrusted A2A counterparty* that
nonetheless issues a **signed** invoice.

Stage 2 of the agentic-commerce loop. The buyer's family agent negotiates with
this service over A2A (here, plain HTTP): it discovers the menu, places an order,
and receives a cart the merchant has **signed with its own Ed25519 key**. That
signed invoice is the hinge — everything downstream (the humans' WebAuthn
approvals, the payment) binds to it, not to the buyer agent's account of the chat.

Why this matters for trust: the buyer agent is talking to a counterparty it does
not control and may be steered by, so *nothing the counterparty says is trusted
on its word*. The one thing that carries weight is the merchant's signature over
concrete terms — and the buyer only honors signatures from merchants whose public
key it has independently placed in its trusted set (see ``/trust-merchant`` on the
approval service). The merchant sets the price authoritatively (from its menu);
the buyer agent cannot dictate it, and cannot alter the signed invoice without
breaking the signature. This is AP2's Cart Mandate: the merchant commits, the
buyer's humans approve exactly that commitment.

The key here is generated at startup for the demo; ``/merchant-card`` publishes
its public key (base64url raw Ed25519) so the buyer can register trust. A
production merchant would persist a stable key and publish it at a well-known
location (the buyer's trust decision is then a one-time, human-made choice).

    uv run python examples/merchant_server.py     # -> http://localhost:7600
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from extensible_mcp_vc.invoice import public_key_from_raw, sign_invoice
from extensible_mcp_vc.settlement import SettlementError, verify_receipt
from extensible_mcp_vc.webauthn import b64url_encode

MERCHANT_ID = "pizza-1"
MERCHANT_NAME = "Tony's Pizza"
QUOTE_TTL_SECONDS = 300  # a quote is good for five minutes, then it must be re-fetched

# The menu is the merchant's authoritative price list; the buyer agent orders by
# name and quantity but never sets the price.
MENU = {
    "Large Pepperoni": 1800,
    "Medium Cheese": 1400,
    "Garlic Knots": 600,
    "Soda": 300,
}

# A per-process merchant identity. See the module docstring on persistence.
_KEY = Ed25519PrivateKey.generate()
_PUBLIC_RAW = b64url_encode(_KEY.public_key().public_bytes_raw())

app = FastAPI(title=f"{MERCHANT_NAME} (A2A merchant agent)")

# Fulfilment state. `_issued` remembers each invoice this merchant signed, keyed
# by its nonce, so a receipt can be matched to the exact order. `_fulfilled`
# tracks nonces already shipped (single-use — a replayed receipt can't re-ship).
# `_settlement_pub` is the payment rail's key the merchant trusts for receipts.
_issued: dict[str, dict[str, Any]] = {}
_fulfilled: set[str] = set()
_settlement_pub: Ed25519PublicKey | None = None


@app.get("/merchant-card")
async def merchant_card() -> JSONResponse:
    """The A2A agent card: who this merchant is and the public key the buyer
    registers into its trusted set to accept this merchant's signed invoices."""
    return JSONResponse(
        {"merchantId": MERCHANT_ID, "merchant": MERCHANT_NAME, "publicKey": _PUBLIC_RAW}
    )


@app.get("/menu")
async def menu() -> JSONResponse:
    return JSONResponse(
        {"items": [{"name": name, "priceCents": price} for name, price in MENU.items()]}
    )


@app.post("/quote")
async def quote(request: Request) -> JSONResponse:
    """A2A order placement: given ``{items:[{name, qty}]}``, price the order from
    the merchant's own menu and return a **signed** invoice. The buyer supplies
    what it wants; the merchant supplies (and commits to) the terms."""
    body = await request.json()
    requested = body.get("items", [])
    if not requested:
        raise HTTPException(400, "empty order")

    line_items, total = [], 0
    for item in requested:
        name = item.get("name")
        qty = int(item.get("qty", 1))
        if name not in MENU:
            raise HTTPException(400, f"no such menu item: {name!r}")
        if qty < 1:
            raise HTTPException(400, f"bad quantity for {name!r}: {qty}")
        total += MENU[name] * qty
        line_items.append({"name": name, "qty": qty})

    invoice = {
        "merchantId": MERCHANT_ID,
        "merchant": MERCHANT_NAME,
        "items": line_items,
        "totalCents": total,
        "currency": "usd",
        "exp": int(time.time()) + QUOTE_TTL_SECONDS,
        "nonce": f"urn:uuid:{uuid.uuid4()}",  # single-use; the buyer/policy rejects replays
    }
    _issued[invoice["nonce"]] = invoice  # remember it so we can match a receipt later
    return JSONResponse({"invoice": invoice, "signature": sign_invoice(invoice, _KEY)})


@app.post("/trust-settlement")
async def trust_settlement(request: Request) -> JSONResponse:
    """Register the payment rail whose signed receipts this merchant will accept
    as proof of payment. ``publicKey`` is base64url raw Ed25519."""
    global _settlement_pub
    body = await request.json()
    _settlement_pub = public_key_from_raw(body["publicKey"])
    return JSONResponse({"trustedSettlement": body["publicKey"]})


@app.post("/fulfill")
async def fulfill(request: Request) -> JSONResponse:
    """Fulfil an order against a **signed payment receipt** — never on the buyer's
    word. The merchant checks the receipt is signed by the trusted rail and
    settles an invoice it actually issued, then ships exactly once."""
    if _settlement_pub is None:
        raise HTTPException(400, "no settlement authority trusted yet")
    body = await request.json()
    receipt = body["receipt"]
    nonce = receipt.get("nonce")
    invoice = _issued.get(nonce)
    if invoice is None:
        raise HTTPException(400, f"no order issued here for nonce {nonce!r}")
    if nonce in _fulfilled:
        raise HTTPException(409, "order already fulfilled")  # single-use receipt
    try:
        verify_receipt(receipt, body["signature"],
                       settlement_key_pub=_settlement_pub, invoice=invoice)
    except SettlementError as e:
        raise HTTPException(400, f"receipt rejected: {e}") from e
    _fulfilled.add(nonce)
    return JSONResponse({
        "status": "fulfilled",
        "nonce": nonce,
        "items": invoice["items"],
        "paymentRef": receipt["paymentRef"],
        "message": f"{MERCHANT_NAME}: your order is being prepared.",
    })


if __name__ == "__main__":
    print(f"{MERCHANT_NAME} on http://localhost:7600  "
          f"(merchantId={MERCHANT_ID}, publicKey={_PUBLIC_RAW})")
    uvicorn.run(app, host="127.0.0.1", port=7600)

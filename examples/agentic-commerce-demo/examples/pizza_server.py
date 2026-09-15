# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tiny mock pizza-ordering backend for the family-network demo.

Runs as a stdio FastMCP server. Three tools:

- ``list_stores`` — ungated. Returns the household's accounts (store
  name, ETA, and menu with prices).
- ``get_menu`` — ungated. Returns one store's menu in detail.
- ``order_pizza`` — gated at the proxy. The kid asks, optionally the
  parent approves, the proxy verifies, then this tool finally records
  the order.

Order confirmations are appended to a log file (default ``pizza-orders.log``
relative to the proxy's working directory) so a demo audience can
``tail -f`` it in a separate terminal and watch orders arrive in real time.
Override the path via the ``PIZZA_ORDERS_LOG`` environment variable.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from extensible_mcp_vc.merchant import (
    MerchantDesk,
    MerchantPolicy,
    default_negotiator,
    load_or_create_key,
)

server = FastMCP(name="pizza")

LOG_FILE = Path(os.environ.get("PIZZA_ORDERS_LOG", "pizza-orders.log"))

# Menus chosen so the three policy tiers are reachable from realistic
# prompts: cheese slice or small cheese stays under $10 (no parent VC
# needed); any large pizza lands in the $10–$200 band (parent VC
# required); 20+ of anything blows past the $200 hard cap and satisfies
# no tier of the governing policy, so it is refused outright.
STORES: dict[str, dict[str, Any]] = {
    "Dominos": {
        "eta_minutes": 30,
        "menu": {
            "cheese slice": 4.00,
            "small cheese": 9.00,
            "small pepperoni": 11.00,
            "large pepperoni": 15.00,
            "large supreme": 22.00,
            "large hawaiian": 20.00,
        },
    },
    "Tony's Pizza": {
        "eta_minutes": 45,
        "menu": {
            "margherita small": 11.00,
            "pepperoni large": 19.00,
            "white pie": 16.00,
        },
    },
    "Pizza Hut": {
        "eta_minutes": 35,
        "menu": {
            "pan small": 9.50,
            "stuffed crust large": 19.00,
            "pepperoni large": 17.00,
        },
    },
}


@server.tool(
    name="list_stores",
    description=(
        "List the pizza stores the household has accounts with. Returns a "
        "JSON object mapping each store name to its menu (pizza type → "
        "unit price in USD) and the store's estimated delivery time in "
        "minutes."
    ),
)
async def list_stores() -> str:
    return json.dumps(STORES, indent=2)


@server.tool(
    name="get_menu",
    description=(
        "Return one store's full menu. The `store` must match a name from "
        "`list_stores`. Use this to look up unit prices before placing an "
        "order with `order_pizza`."
    ),
)
async def get_menu(store: str) -> str:
    if store not in STORES:
        return (
            f"Unknown store '{store}'. Use list_stores to see available stores."
        )
    return json.dumps(STORES[store], indent=2)


@server.tool(
    name="order_pizza",
    description=(
        "Place a pizza order. `total` is the dollar amount the household "
        "will be charged (unit price × quantity, looked up via `get_menu`). "
        "The proxy's policy filter uses `total` to decide whether parental "
        "authorization is required and whether the order is permitted at "
        "all. The backend re-checks against its own menu and rejects "
        "mismatched totals."
    ),
)
async def order_pizza(
    pizza_type: str,
    store: str,
    address: str,
    quantity: int = 1,
    total: float | None = None,
) -> str:
    if store not in STORES:
        return (
            f"Unknown store '{store}'. Use list_stores to see available stores."
        )
    menu = STORES[store]["menu"]
    if pizza_type not in menu:
        return (
            f"Unknown pizza '{pizza_type}' at {store}. Use get_menu({store!r}) "
            "to see what's available."
        )
    unit_price = float(menu[pizza_type])
    computed_total = round(unit_price * quantity, 2)
    if total is not None and abs(float(total) - computed_total) > 0.01:
        return (
            f"Total mismatch: backend computed ${computed_total:.2f} for "
            f"{quantity}× {pizza_type} at {store} (unit ${unit_price:.2f}), "
            f"but the request claimed ${float(total):.2f}. Refusing to "
            "place the order."
        )
    eta = STORES[store]["eta_minutes"]
    timestamp = datetime.now().isoformat(timespec="seconds")
    log_line = (
        f"[{timestamp}] ORDER PLACED: {quantity}x {pizza_type} from {store} "
        f"-> {address} (total ${computed_total:.2f}, ETA {eta} min)\n"
    )
    with LOG_FILE.open("a") as f:
        f.write(log_line)
    return (
        f"Order placed: {quantity}x {pizza_type} from {store}, delivering "
        f"to {address}. Total ${computed_total:.2f}. ETA {eta} minutes."
    )


# --------------------------------------------------------------------------- #
# The merchant's agent desk (Domino's): an LLM clerk negotiates, the merchant
# policy gates what its signature can bind. The org's standing delegation of
# authority — the counterpart of the family's per-action human approvals.
#
# Domino's, not Tony's Pizza: its menu has items at or under the $10 solo-
# approval threshold ("cheese slice" $4, "small cheese" $9), so the child-
# only approval path is reachable with a real order, not just a negotiated
# discount.
# --------------------------------------------------------------------------- #

_MERCHANT_STORE = "Dominos"
_MERCHANT_NAME = "Domino's"
_MENU_CENTS = {
    name: int(round(price * 100)) for name, price in STORES[_MERCHANT_STORE]["menu"].items()
}
_DESK = MerchantDesk(
    merchant_id="dominos",
    merchant_name=_MERCHANT_NAME,
    policy=MerchantPolicy(menu=_MENU_CENTS),
    key=load_or_create_key(
        os.environ.get("MERCHANT_KEY_PATH", "pizza-merchant.key")
    ),
    negotiator=default_negotiator(_MERCHANT_NAME),
)


@server.tool(
    name="merchant_card",
    description=(
        f"{_MERCHANT_NAME} agent card: merchant id, display name, and the "
        "public key to register into your trusted-merchant set before "
        "honoring its signed invoices."
    ),
)
async def merchant_card() -> dict:
    return _DESK.card()


# Plain-HTTP twin of merchant_card for boot-time trust exchange: the family
# side curls this and registers the key into its trusted-merchant set —
# a deployment decision made outside any LLM's reach.
@server.custom_route("/merchant-card", methods=["GET"])
async def merchant_card_http(request):
    from starlette.responses import JSONResponse

    return JSONResponse(_DESK.card())


@server.tool(
    name="negotiate",
    description=(
        f"Talk to {_MERCHANT_NAME} sales agent: ask questions, haggle, or "
        "propose an order (`order` is a list of {name, qty, priceCents?}). "
        "Returns the clerk's reply and, when it proposes concrete terms, an "
        "order proposal. Nothing here is binding — only a signed invoice "
        "from request_invoice commits the merchant."
    ),
)
async def negotiate(message: str, order: list[dict] | None = None) -> dict:
    return _DESK.negotiate(message, order)


@server.tool(
    name="request_invoice",
    description=(
        f"Ask {_MERCHANT_NAME} to sign an invoice for `items` "
        "([{name, qty, priceCents?}]; omitted prices fill at list), "
        "optionally with `deliver_to` (delivery address, bound inside the "
        "signed terms). Returns {invoice, signature} — the merchant's "
        "binding commitment — or a refusal with the policy violations if "
        "the terms exceed what the merchant's clerk is authorized to sign."
    ),
)
async def request_invoice(items: list[dict], deliver_to: str | None = None) -> dict:
    return _DESK.invoice(items, deliver_to=deliver_to)


# The settlement authority whose signed receipts this merchant accepts as
# proof of payment. Fetched once from the family's approval service — a
# boot/config-time trust decision of the merchant org, not an LLM-mediated
# one (an agent must not be able to swap the rail this parlor trusts).
_SETTLEMENT_URL = os.environ.get("SETTLEMENT_URL", "http://localhost:7500")
_settlement_pub = None


async def _get_settlement_pub():
    global _settlement_pub
    if _settlement_pub is None:
        import httpx

        from extensible_mcp_vc.invoice import public_key_from_raw

        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"{_SETTLEMENT_URL}/settlement-card")
            r.raise_for_status()
            _settlement_pub = public_key_from_raw(r.json()["publicKey"])
    return _settlement_pub


@server.tool(
    name="fulfill",
    description=(
        "Present a signed payment receipt ({receipt, signature} from the "
        f"settlement rail) to {_MERCHANT_NAME} to schedule the delivery. The "
        "merchant verifies the receipt against the rail it trusts and the "
        "invoice it actually issued (single-use), then returns a "
        "merchant-signed fulfillment commitment {commitment, signature} — "
        "the closing artifact of the purchase."
    ),
)
async def fulfill(receipt: dict, signature: str) -> dict:
    try:
        settlement_pub = await _get_settlement_pub()
    except Exception as e:  # noqa: BLE001 - rail unreachable -> refuse, don't ship
        return {"error": f"cannot verify receipts: settlement authority unreachable ({e})"}
    result = _DESK.fulfill(receipt, signature, settlement_pub=settlement_pub)
    if "commitment" in result:
        c = result["commitment"]
        with LOG_FILE.open("a") as f:
            f.write(
                json.dumps(
                    {"time": datetime.now().isoformat(timespec="seconds"),
                     "fulfilled": c["items"], "nonce": c["nonce"],
                     "deliverTo": c.get("deliverTo"), "paymentRef": c["paymentRef"]}
                ) + "\n"
            )
    return result


if __name__ == "__main__":
    # stdio child of the proxy by default; PIZZA_PORT serves Streamable HTTP
    # instead — the pizza parlor as its own service (its own container),
    # reached across the org boundary like any remote MCP server.
    port = os.environ.get("PIZZA_PORT")
    if port:
        server.run(
            transport="http",
            host=os.environ.get("PIZZA_HOST", "0.0.0.0"),
            port=int(port),
        )
    else:
        server.run()

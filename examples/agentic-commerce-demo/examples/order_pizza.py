# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Drive the buyer side end to end: negotiate, get it approved, and fulfil.

This is the family agent's orchestration for the whole loop (stages 1-3). It runs
every step that does *not* require a human biometric — discover the merchant,
register trust, negotiate a signed invoice, submit it for approval — then waits
for the kid and parent to approve in the browser. Once they do, the approval
service charges the rail for the invoice's terms and signs a receipt; this driver
relays that receipt to the merchant, which verifies it and ships the order.

Start the two services first, then run this:

    uv run python examples/merchant_server.py      # terminal 1 -> :7600
    uv run python examples/approval_service.py     # terminal 2 -> :7500
    uv run python examples/order_pizza.py          # terminal 3

    # order something else:
    uv run python examples/order_pizza.py --item "Medium Cheese" --item "Soda:2"

    # real test-mode Stripe instead of the mock rail (approval service):
    SETTLEMENT=stripe STRIPE_API_KEY=sk_test_… uv run python examples/approval_service.py

Trust is registered here from the published cards for demo convenience. In
production, trusting a merchant key or the rail's receipt key is a deliberate,
human-made, out-of-band decision — not something the negotiation can influence.
"""

from __future__ import annotations

import argparse
import time

import httpx

from extensible_mcp_vc.invoice import public_key_from_raw
from extensible_mcp_vc.negotiate import (
    fetch_menu,
    fetch_merchant_card,
    negotiate_order,
)


def _parse_items(specs: list[str]) -> list[dict]:
    """Each spec is ``"Name"`` or ``"Name:qty"``."""
    items = []
    for spec in specs:
        name, _, qty = spec.partition(":")
        items.append({"name": name, "qty": int(qty) if qty else 1})
    return items


def main() -> None:
    parser = argparse.ArgumentParser(prog="order_pizza")
    parser.add_argument("--merchant", default="http://localhost:7600")
    parser.add_argument("--approvals", default="http://localhost:7500")
    parser.add_argument("--item", action="append", dest="items", metavar="NAME[:QTY]",
                        help="repeatable; defaults to one Large Pepperoni")
    parser.add_argument("--wait", type=int, default=180,
                        help="seconds to wait for human approval before giving up")
    args = parser.parse_args()
    order = _parse_items(args.items) if args.items else [{"name": "Large Pepperoni", "qty": 1}]

    merchant = httpx.Client(base_url=args.merchant, timeout=30.0)
    approvals = httpx.Client(base_url=args.approvals, timeout=30.0)

    # 1. Discover the merchant and register the two trust decisions (the human's):
    #    the buyer trusts the merchant's key, the merchant trusts the rail's key.
    card = fetch_merchant_card(merchant)
    print(f"merchant: {card['merchant']} ({card['merchantId']})")
    approvals.post("/trust-merchant",
                   json={"merchantId": card["merchantId"], "publicKey": card["publicKey"]}
                   ).raise_for_status()
    rail = approvals.get("/settlement-card").json()
    merchant.post("/trust-settlement", json={"publicKey": rail["publicKey"]}).raise_for_status()
    print("registered the merchant and the settlement rail into the trusted sets")

    menu = {i["name"]: i["priceCents"] for i in fetch_menu(merchant)}
    print("menu:", ", ".join(f"{n} ${p / 100:.2f}" for n, p in menu.items()))

    # 2. Negotiate over A2A — verify the returned invoice at the agent boundary.
    trusted = {card["merchantId"]: public_key_from_raw(card["publicKey"])}
    invoice, signature = negotiate_order(merchant, order, trusted_merchants=trusted)
    lines = ", ".join(f"{i['qty']}x {i['name']}" for i in invoice["items"])
    print(f"negotiated invoice: {lines} = ${invoice['totalCents'] / 100:.2f} "
          f"(nonce {invoice['nonce']})")

    # 3. Submit the signed invoice for human approval.
    r = approvals.post("/request-invoice", json={"invoice": invoice, "signature": signature})
    r.raise_for_status()
    summary = r.json()
    approval_id = summary["id"]
    print(f"\nsubmitted for approval (id {approval_id}); "
          f"needs: {', '.join(summary['required_roles'])}")
    print(f"-> open {args.approvals}/ and approve as each required role "
          f"(biometric binds to this exact invoice)")

    # 4. Wait for the humans to approve; the approval service settles on the rail.
    print(f"\nwaiting up to {args.wait}s for approval + settlement…")
    deadline = time.monotonic() + args.wait
    receipt = receipt_sig = None
    last = None
    while time.monotonic() < deadline:
        s = approvals.get(f"/pending/{approval_id}").json()
        if s["status"] != last:
            print(f"  status: {s['status']}"
                  + (f" (approved: {', '.join(s['approved_roles']) or 'none'})"
                     if s["status"] != "settled" else ""))
            last = s["status"]
        if s.get("settlement_error"):
            print(f"payment declined: {s['settlement_error']}")
            return
        if s["status"] == "settled":
            receipt, receipt_sig = s["receipt"], s["receipt_signature"]
            break
        time.sleep(2)
    if receipt is None:
        print("gave up waiting for approval; re-run once approved.")
        return
    print(f"paid: {receipt['paymentRef']} (${receipt['amountCents'] / 100:.2f})")

    # 5. Relay the signed receipt to the merchant, which verifies it and ships.
    f = merchant.post("/fulfill", json={"receipt": receipt, "signature": receipt_sig})
    f.raise_for_status()
    out = f.json()
    lines = ", ".join(f"{i['qty']}x {i['name']}" for i in out["items"])
    print(f"fulfilled: {lines} — {out['message']}")


if __name__ == "__main__":
    main()

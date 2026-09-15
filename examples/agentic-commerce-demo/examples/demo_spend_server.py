# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Minimal downstream payments server for the policy-bundle boot demo.

Identical in spirit to ``payments_server.py`` but its ``spend`` tool speaks
``merchant`` (not ``vendor``), matching the ``family_spend_prod`` policy's
call-binding fields, so the demo can exercise a clean allow. The proxy in
front gates ``spend`` behind the supplied VC policy bundle; this backend only
sees calls the policy already approved.
"""

from __future__ import annotations

from fastmcp import FastMCP

server = FastMCP(name="payments")
_state: dict[str, object] = {"balance": 100.0, "log": []}


@server.tool(
    name="spend",
    description=(
        "Spend `amount` dollars at `merchant`. Debits the running balance and "
        "returns a confirmation string with the new balance."
    ),
)
async def spend(amount: float, merchant: str) -> str:
    balance = float(_state["balance"])
    if amount > balance:
        return f"insufficient funds (balance ${balance:.2f}, requested ${amount:.2f})"
    new_balance = balance - amount
    _state["balance"] = new_balance
    _state["log"].append({"amount": amount, "merchant": merchant})  # type: ignore[union-attr]
    return f"OK. Spent ${amount:.2f} at {merchant}. New balance: ${new_balance:.2f}."


if __name__ == "__main__":
    server.run()

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tiny mock payments backend for the family-network demo.

Runs as a stdio FastMCP server with one piece of in-memory state (a balance)
and two tools: ``spend`` and ``balance``. The proxy in front of it gates
``spend`` behind a verifiable-credential chain; ``balance`` is open.
"""

from __future__ import annotations

from fastmcp import FastMCP

server = FastMCP(name="payments")
_state: dict[str, float | list[dict]] = {"balance": 100.0, "log": []}


@server.tool(
    name="spend",
    description=(
        "Spend `amount` dollars at `vendor`. Debits the running balance and "
        "appends to the spend log. Returns a confirmation string with the "
        "new balance."
    ),
)
async def spend(amount: float, vendor: str) -> str:
    balance = float(_state["balance"])
    if amount > balance:
        return f"insufficient funds (balance ${balance:.2f}, requested ${amount:.2f})"
    new_balance = balance - amount
    _state["balance"] = new_balance
    _state["log"].append({"amount": amount, "vendor": vendor})  # type: ignore[union-attr]
    return f"OK. Spent ${amount:.2f} at {vendor}. New balance: ${new_balance:.2f}."


@server.tool(
    name="balance",
    description="Return the current balance as a string.",
)
async def balance() -> str:
    return f"Balance: ${float(_state['balance']):.2f}"


if __name__ == "__main__":
    server.run()

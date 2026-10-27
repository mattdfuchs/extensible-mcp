# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""A fake payments server with the one tool the minimal bundle governs.

``send`` takes exactly the native arguments the ``minimal_spend`` request
credential binds (``amountCents``, ``merchant``), so a call that reaches it
has had its credential stripped by the policy filter — the downstream never
declares ``requestVC`` and would refuse it.
"""

from fastmcp import FastMCP

mock_payments = FastMCP("mock-payments")


@mock_payments.tool(name="send", description="Send money to a merchant")
def send(amountCents: int, merchant: str) -> str:  # noqa: N803 - the policy's own names
    """Send ``amountCents`` to ``merchant``."""
    return f"sent {amountCents} to {merchant}"


if __name__ == "__main__":
    mock_payments.run()

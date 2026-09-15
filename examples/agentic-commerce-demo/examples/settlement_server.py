# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""A tiny settlement bridge, downstream of the proxy's gated call path.

All settlement state — the rail credential, the executor, the signed
receipt — stays inside ``approval_service.py``; this process holds none of
it. It exists purely so ``charge_invoice`` can be a normal downstream MCP
tool the proxy's ``BundleRouter`` gates on the certified
``family_spend_invoice`` policy, the same shape
``spend``/``order_pizza`` already have. By the time a call reaches this
tool, the policy has already verified the merchant's signature, that the
invoice binds this exact call, and that every required passkey approval
is valid and bound to this exact invoice — this tool never re-decides
authorization, it only executes and reports back to the approval service
(which still owns the audit trail).
"""

from __future__ import annotations

import os
from typing import Any

import httpx
from fastmcp import FastMCP

server = FastMCP(name="settlement")

APPROVAL_URL = os.environ.get("APPROVAL_URL", "http://localhost:7500")


@server.tool(
    name="charge_invoice",
    description=(
        "Charge the payment rail for an already-approved invoice and return "
        "a settlement-signed receipt {receipt, receipt_signature}. Only "
        "reachable once the proxy's policy has verified the merchant's "
        "signature, that the invoice binds this call, and every required "
        "passkey approval — this tool never re-decides authorization, it "
        "only executes. `amountCents`/`merchantId` are the same claims the "
        "policy already bound to the signed invoice; pass them exactly as "
        "given to `request_invoice_approval`."
    ),
)
async def charge_invoice(amountCents: int, merchantId: str) -> dict[str, Any]:
    async with httpx.AsyncClient(base_url=APPROVAL_URL, timeout=30.0) as client:
        try:
            r = await client.post(
                "/settle", json={"merchantId": merchantId, "amountCents": amountCents}
            )
        except httpx.RequestError as e:
            return {"error": f"could not reach the approval/settlement service: {e}"}
    if r.status_code != 200:
        return {"error": f"settlement refused: {r.text}"}
    body = r.json()
    return {"receipt": body["receipt"], "receipt_signature": body["receipt_signature"]}


if __name__ == "__main__":
    server.run()

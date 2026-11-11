# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""``request_invoice_approval`` and ``approval_result`` (the standalone
functions meta_tools.py's ``LocalTool`` handlers delegate to): the first
opens a passkey-approval task bound to a merchant-signed invoice and
returns at once; the second fetches the task's outcome by id, which once
``completed`` is the evidence for a *following*, separately gated
``charge_invoice`` call — neither settles anything itself.

Bound directly to ``approval_service.py``'s real FastAPI app via
``httpx.ASGITransport`` — no sockets, no ports, the real WebAuthn
verification and invoice-signature checks — same pattern as
``test_meta_tools.py``'s wallet tests and ``test_purchase.py``'s
``TestClient``-based ones, just async.
"""

from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from extensible_mcp_vc.invoice import invoice_challenge, sign_invoice
from extensible_mcp_vc.meta_tools import approval_result, request_invoice_approval
from extensible_mcp_vc.webauthn import b64url_encode

from .webauthn_fixtures import (
    assertion_for,
    attestation_object,
    load_approval_module,
    sign_in_async,
)

FUTURE = 4_000_000_000  # year 2096, so the expiry check is never the reason a test fails


@pytest.fixture
def approval_mod():
    # Shared loader: isolates VC_WORKSPACE, so importing the service does not
    # write approval-users.json into the repo's real workspace.
    return load_approval_module()


def _client_for(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )


def _invoice(**over):
    inv = {
        "merchantId": "pizza-1", "merchant": "Dominos",
        "items": [{"name": "cheese slice", "qty": 1}],
        "totalCents": 400, "currency": "usd", "exp": FUTURE,
        "nonce": "urn:uuid:meta-1",
    }
    inv.update(over)
    return inv


async def _enroll(client, role, store):
    """Sign in as ``role``, then enrol a passkey under it. The role comes from
    the token; nothing is sent in the body."""
    headers = await sign_in_async(client, role, store)
    key = ec.generate_private_key(ec.SECP256R1())
    cred_id = f"cred-{role}".encode()
    r = await client.post("/register", json={
        "attestationObject": b64url_encode(attestation_object(key.public_key(), cred_id)),
    }, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["role"] == role
    return key, r.json()["credentialId"]


async def _trust_merchant(client, merchant_key, merchant_id="pizza-1"):
    raw = b64url_encode(merchant_key.public_key().public_bytes_raw())
    r = await client.post("/trust-merchant", json={"merchantId": merchant_id, "publicKey": raw})
    assert r.status_code == 200


async def _approve(client, task_id, key, cred_id, challenge, headers):
    return await client.post(
        f"/approve/{task_id}",
        json={"credentialId": cred_id, **assertion_for(key, challenge)},
        headers=headers,
    )


async def test_the_request_returns_at_once_as_an_input_required_task(approval_mod):
    merchant_key = Ed25519PrivateKey.generate()
    async with _client_for(approval_mod.app) as client:
        await _trust_merchant(client, merchant_key)
        invoice = _invoice()
        signature = sign_invoice(invoice, merchant_key)

        task = await request_invoice_approval(client, invoice, signature)

        assert task["status"] == "input_required"
        assert task["required_roles"] == ["child"]
        assert task["expires_at"] == invoice["exp"]  # the merchant's window
        assert "child" in task["status_message"]
        assert "invoice" not in task and "childApproval" not in task  # no evidence yet

        # the outcome by id, while the humans have not acted
        waiting = await approval_result(client, task["task_id"])
        assert waiting["status"] == "input_required"
        assert "still waiting for child" in waiting["status_message"]


async def test_solo_completion_yields_the_evidence_not_a_receipt(approval_mod):
    """Solo tier ($4, under the $10 threshold): only the child leg is
    required, and the completed task carries the evidence for
    charge_invoice — not a receipt, since nothing here settles."""
    merchant_key = Ed25519PrivateKey.generate()
    async with _client_for(approval_mod.app) as client:
        await _trust_merchant(client, merchant_key)
        store = approval_mod._users
        child_headers = await sign_in_async(client, "child", store)
        child_key, child_cred_id = await _enroll(client, "child", store)

        invoice = _invoice()
        signature = sign_invoice(invoice, merchant_key)
        task = await request_invoice_approval(client, invoice, signature)
        r = await _approve(client, task["task_id"], child_key, child_cred_id,
                           invoice_challenge(invoice), child_headers)
        assert r.status_code == 200

        result = await approval_result(client, task["task_id"])

    assert result["status"] == "completed"
    assert result["task_id"] == task["task_id"]
    assert "error" not in result and "receipt" not in result
    # invoice comes back as ONE object with the merchant's signature
    # embedded — matching charge_invoice's single `invoice` credential
    # field — fetched by id, so the requester never had to keep a copy.
    assert result["invoice"] == {**invoice, "signature": signature}
    assert result["childApproval"]["credentialId"] == child_cred_id
    assert "parentApproval" not in result  # not required at this amount


async def test_dual_tier_is_input_required_until_both_legs_have_signed(approval_mod):
    merchant_key = Ed25519PrivateKey.generate()
    async with _client_for(approval_mod.app) as client:
        await _trust_merchant(client, merchant_key)
        store = approval_mod._users
        child_headers = await sign_in_async(client, "child", store)
        parent_headers = await sign_in_async(client, "parent", store)
        child_key, child_cred_id = await _enroll(client, "child", store)
        parent_key, parent_cred_id = await _enroll(client, "parent", store)

        invoice = _invoice(totalCents=1500, nonce="urn:uuid:meta-dual")
        signature = sign_invoice(invoice, merchant_key)
        challenge = invoice_challenge(invoice)
        task = await request_invoice_approval(client, invoice, signature)
        assert task["required_roles"] == ["child", "parent"]

        await _approve(client, task["task_id"], child_key, child_cred_id, challenge, child_headers)
        half = await approval_result(client, task["task_id"])
        assert half["status"] == "input_required"
        assert "still waiting for parent" in half["status_message"]

        await _approve(client, task["task_id"], parent_key, parent_cred_id, challenge, parent_headers)
        result = await approval_result(client, task["task_id"])

    assert result["status"] == "completed"
    assert result["childApproval"]["credentialId"] == child_cred_id
    assert result["parentApproval"]["credentialId"] == parent_cred_id


async def test_untrusted_merchant_errors_immediately(approval_mod):
    rogue_key = Ed25519PrivateKey.generate()  # never registered
    invoice = _invoice(nonce="urn:uuid:meta-untrusted")
    signature = sign_invoice(invoice, rogue_key)
    async with _client_for(approval_mod.app) as client:
        result = await request_invoice_approval(client, invoice, signature)
    assert "error" in result and "trusted set" in result["error"]


async def test_a_task_whose_window_closed_fails_and_an_unknown_one_fails(approval_mod):
    merchant_key = Ed25519PrivateKey.generate()
    async with _client_for(approval_mod.app) as client:
        await _trust_merchant(client, merchant_key)
        invoice = _invoice(nonce="urn:uuid:meta-expired")
        signature = sign_invoice(invoice, merchant_key)
        task = await request_invoice_approval(client, invoice, signature)
        approval_mod._pending[task["task_id"]]["exp"] = 0  # the window closes
        failed = await approval_result(client, task["task_id"])
        unknown = await approval_result(client, "no-such-task")
    assert failed["status"] == "failed" and "expired" in failed["status_message"]
    assert unknown["status"] == "failed" and "unknown" in unknown["status_message"]

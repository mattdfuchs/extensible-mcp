# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""``request_invoice_approval`` (the standalone function meta_tools.py's
``@server.tool`` wrapper delegates to): collects passkey approvals bound
to a merchant-signed invoice and hands back evidence for a *following*,
separately gated ``charge_invoice`` call — it settles nothing itself.

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
from extensible_mcp_vc.meta_tools import request_invoice_approval
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


async def _approve_once_pending(client, key, cred_id, challenge, headers):
    """Poll ``/pending`` until the invoice this test just submitted shows
    up, then approve it — mirrors what the browser page does, at the speed
    a test needs rather than a human's."""
    for _ in range(50):
        r = await client.get("/pending")
        if r.status_code == 200:
            j = r.json()
            return await client.post(
                f"/approve/{j['id']}",
                json={"credentialId": cred_id, **assertion_for(key, challenge)},
                headers=headers,
            )
        await asyncio.sleep(0.02)
    raise AssertionError("invoice never became pending")


async def test_returns_evidence_not_a_receipt_once_solo_approved(approval_mod):
    """Solo tier ($4, under the $10 threshold): only the child leg is
    required, and success returns collected evidence for charge_invoice —
    not a receipt, since this function never settles anything."""
    merchant_key = Ed25519PrivateKey.generate()
    async with _client_for(approval_mod.app) as client:
        await _trust_merchant(client, merchant_key)
        store = approval_mod._users
        child_headers = await sign_in_async(client, "child", store)
        child_key, child_cred_id = await _enroll(client, "child", store)

        invoice = _invoice()
        signature = sign_invoice(invoice, merchant_key)
        challenge = invoice_challenge(invoice)

        approver = asyncio.create_task(
            _approve_once_pending(client, child_key, child_cred_id, challenge,
                                  child_headers)
        )
        result = await request_invoice_approval(
            client, invoice, signature, poll_interval_seconds=0.02, timeout_seconds=5.0,
        )
        approve_response = await approver
        assert approve_response.status_code == 200

    assert result["status"] == "approved"
    assert "error" not in result
    assert "receipt" not in result  # the whole point: no auto-settlement
    # invoice comes back as ONE object with the merchant's signature
    # embedded — matching charge_invoice's single `invoice` credential
    # field, not two separate values the caller would need to recombine.
    assert result["invoice"] == {**invoice, "signature": signature}
    assert result["childApproval"]["credentialId"] == child_cred_id
    assert "parentApproval" not in result  # not required at this amount


async def test_dual_tier_waits_for_both_legs(approval_mod):
    """Above $10: the function must not return until *both* legs have
    approved, and both assertions come back."""
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

        async def _approve_both():
            r1 = await _approve_once_pending(client, child_key, child_cred_id, challenge,
                                             child_headers)
            assert r1.status_code == 200
            assert r1.json()["status"] == "pending"  # child alone isn't enough
            r2 = await client.post(
                f"/approve/{r1.json()['id']}",
                json={"credentialId": parent_cred_id, **assertion_for(parent_key, challenge)},
                headers=parent_headers,
            )
            assert r2.status_code == 200
            return r2

        approver = asyncio.create_task(_approve_both())
        result = await request_invoice_approval(
            client, invoice, signature, poll_interval_seconds=0.02, timeout_seconds=5.0,
        )
        await approver

    assert result["status"] == "approved"
    assert result["childApproval"]["credentialId"] == child_cred_id
    assert result["parentApproval"]["credentialId"] == parent_cred_id


async def test_untrusted_merchant_errors_immediately_no_polling(approval_mod):
    rogue_key = Ed25519PrivateKey.generate()  # never registered
    invoice = _invoice(nonce="urn:uuid:meta-untrusted")
    signature = sign_invoice(invoice, rogue_key)
    async with _client_for(approval_mod.app) as client:
        result = await request_invoice_approval(
            client, invoice, signature, poll_interval_seconds=0.02, timeout_seconds=5.0,
        )
    assert "error" in result and "trusted set" in result["error"]


async def test_timeout_when_nobody_approves(approval_mod):
    merchant_key = Ed25519PrivateKey.generate()
    async with _client_for(approval_mod.app) as client:
        await _trust_merchant(client, merchant_key)
        invoice = _invoice(nonce="urn:uuid:meta-timeout")
        signature = sign_invoice(invoice, merchant_key)
        result = await request_invoice_approval(
            client, invoice, signature, poll_interval_seconds=0.02, timeout_seconds=0.1,
        )
    assert "error" in result and "not fully approved" in result["error"]

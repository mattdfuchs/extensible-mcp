# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Stage 3 end-to-end: the whole loop from a request to a shipped order.

Negotiate a signed invoice, have child + parent approve it, watch the approval
service settle it on the (mock) rail and emit a signed receipt, then fulfil the
order at the merchant against that receipt. Every hop carries verifiable signed
evidence; the merchant ships only against a receipt that verifies, only for an
order it issued, and only once.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from extensible_mcp_vc.invoice import invoice_challenge
from extensible_mcp_vc.negotiate import negotiate_order
from extensible_mcp_vc.settlement import payment_receipt, sign_receipt
from extensible_mcp_vc.webauthn import b64url_encode

from .webauthn_fixtures import assertion_for, attestation_object

ORDER = [{"name": "Large Pepperoni", "qty": 1}]  # 1800 cents -> child + parent


def _load(rel: str, name: str):
    path = Path(__file__).resolve().parents[1] / rel
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def merchant():
    return TestClient(_load("examples/merchant_server.py", "merchant_server").app)


@pytest.fixture
def approvals():
    return TestClient(_load("examples/approval_service.py", "approval_service").app)


def _enroll(client, role):
    key = ec.generate_private_key(ec.SECP256R1())
    r = client.post("/register", json={
        "attestationObject": b64url_encode(attestation_object(key.public_key(), f"cred-{role}".encode())),
        "role": role})
    assert r.status_code == 200
    return key, r.json()["credentialId"]


def _wire_trust(approvals, merchant):
    """The two out-of-band trust decisions: the buyer trusts the merchant's key,
    the merchant trusts the rail's receipt key."""
    card = merchant.get("/merchant-card").json()
    approvals.post("/trust-merchant",
                   json={"merchantId": card["merchantId"], "publicKey": card["publicKey"]})
    rail = approvals.get("/settlement-card").json()
    merchant.post("/trust-settlement", json={"publicKey": rail["publicKey"]})


def _approve_fully(approvals, req_id, invoice):
    ck, cid = _enroll(approvals, "child")
    pk, pid = _enroll(approvals, "parent")
    ch = invoice_challenge(invoice)
    approvals.post(f"/approve/{req_id}", json={"credentialId": cid, **assertion_for(ck, ch)})
    return approvals.post(f"/approve/{req_id}", json={"credentialId": pid, **assertion_for(pk, ch)})


def _approve_and_settle(approvals, req_id, invoice):
    """Full approval, then the now-separate, explicit settlement step."""
    approved = _approve_fully(approvals, req_id, invoice).json()
    assert approved["status"] == "approved"
    return approvals.post(
        "/settle",
        json={
            "merchantId": invoice["merchantId"],
            "amountCents": invoice["totalCents"],
            "nonce": invoice["nonce"],
        },
    )


# -- the whole loop ---------------------------------------------------------- #
def test_negotiate_approve_settle_fulfill(merchant, approvals):
    _wire_trust(approvals, merchant)
    invoice, sig = negotiate_order(merchant, ORDER)
    req = approvals.post("/request-invoice", json={"invoice": invoice, "signature": sig}).json()

    settled = _approve_and_settle(approvals, req["id"], invoice).json()
    # The service that verified the humans' consent charged the rail and signed a receipt.
    assert settled["status"] == "settled"
    assert settled["receipt"]["amountCents"] == 1800
    assert settled["receipt"]["nonce"] == invoice["nonce"]

    # The buyer relays that receipt to the merchant, who verifies and ships.
    r = merchant.post("/fulfill", json={
        "receipt": settled["receipt"], "signature": settled["receipt_signature"]})
    assert r.status_code == 200
    out = r.json()
    assert out["status"] == "fulfilled" and out["items"] == ORDER


def test_receipt_cannot_ship_twice(merchant, approvals):
    _wire_trust(approvals, merchant)
    invoice, sig = negotiate_order(merchant, ORDER)
    req = approvals.post("/request-invoice", json={"invoice": invoice, "signature": sig}).json()
    settled = _approve_and_settle(approvals, req["id"], invoice).json()
    payload = {"receipt": settled["receipt"], "signature": settled["receipt_signature"]}

    assert merchant.post("/fulfill", json=payload).status_code == 200
    replay = merchant.post("/fulfill", json=payload)  # same receipt again
    assert replay.status_code == 409 and "already fulfilled" in replay.json()["detail"]


def test_fulfill_refused_before_a_rail_is_trusted(merchant, approvals):
    # Only the buyer<->merchant trust is wired, not the rail's receipt key.
    card = merchant.get("/merchant-card").json()
    approvals.post("/trust-merchant",
                   json={"merchantId": card["merchantId"], "publicKey": card["publicKey"]})
    invoice, sig = negotiate_order(merchant, ORDER)
    req = approvals.post("/request-invoice", json={"invoice": invoice, "signature": sig}).json()
    settled = _approve_and_settle(approvals, req["id"], invoice).json()
    r = merchant.post("/fulfill", json={
        "receipt": settled["receipt"], "signature": settled["receipt_signature"]})
    assert r.status_code == 400 and "no settlement authority" in r.json()["detail"]


def test_forged_receipt_refused(merchant, approvals):
    _wire_trust(approvals, merchant)
    invoice, sig = negotiate_order(merchant, ORDER)  # a genuinely issued order
    # An imposter signs a well-formed receipt for that real order.
    forged = payment_receipt(invoice, "mock_pi_forged", "succeeded")
    forged_sig = sign_receipt(forged, Ed25519PrivateKey.generate())
    r = merchant.post("/fulfill", json={"receipt": forged, "signature": forged_sig})
    assert r.status_code == 400 and "signature" in r.json()["detail"]


def test_receipt_for_an_unissued_order_refused(merchant, approvals):
    _wire_trust(approvals, merchant)
    # A receipt whose nonce this merchant never issued: rejected before any crypto.
    phantom = {"nonce": "urn:uuid:never", "merchantId": "pizza-1", "amountCents": 1800,
               "currency": "usd", "paymentRef": "mock_pi_x", "status": "succeeded"}
    r = merchant.post("/fulfill", json={"receipt": phantom, "signature": "AA"})
    assert r.status_code == 400 and "no order issued here" in r.json()["detail"]

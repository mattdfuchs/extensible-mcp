# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Stage 1 end-to-end: a merchant-signed invoice becomes the object the humans
approve and the rail pays.

The buyer registers a merchant into its closed trusted set, the merchant issues a
signed invoice, and the kid + parent approve it with WebAuthn — each biometric
bound to the *invoice hash*, not to any buyer-agent summary of a negotiation.
Authorization lands only once both required roles have signed that exact invoice.

The refusals are the point: an invoice from an unknown merchant, a tampered
invoice, or an expired one never reaches the humans; and an approval signed for a
*different* invoice cannot authorize this one.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from extensible_mcp_vc.invoice import invoice_challenge, sign_invoice
from extensible_mcp_vc.webauthn import b64url_decode, b64url_encode

from .webauthn_fixtures import assertion_for as _assertion_for
from .webauthn_fixtures import attestation_object as _attestation_object

# A far-future / far-past expiry so the wall-clock check in the endpoint is
# deterministic (the endpoint verifies invoices against real time).
FUTURE = 4_000_000_000  # year 2096
PAST = 1  # 1970


def _load_app():
    path = Path(__file__).resolve().parents[1] / "examples" / "approval_service.py"
    spec = importlib.util.spec_from_file_location("approval_service", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.app


@pytest.fixture
def client():
    return TestClient(_load_app())


def _enroll(client, role):
    key = ec.generate_private_key(ec.SECP256R1())
    cred_id = f"cred-{role}".encode()
    r = client.post("/register", json={
        "attestationObject": b64url_encode(_attestation_object(key.public_key(), cred_id)),
        "role": role})
    assert r.status_code == 200
    return key, r.json()["credentialId"]


def _merchant(client, merchant_id="pizza-1"):
    """Mint a merchant key and register its public key into the trusted set."""
    key = Ed25519PrivateKey.generate()
    raw = b64url_encode(key.public_key().public_bytes_raw())
    r = client.post("/trust-merchant", json={"merchantId": merchant_id, "publicKey": raw})
    assert r.status_code == 200 and merchant_id in r.json()["trusted"]
    return key


def _invoice(**over):
    inv = {
        "merchantId": "pizza-1",
        "merchant": "Tony's Pizza",
        "items": [{"name": "Large Pepperoni", "qty": 1}],
        "totalCents": 1800,  # > $10 -> needs child + parent
        "currency": "usd",
        "exp": FUTURE,
        "nonce": "urn:uuid:inv-1",
    }
    inv.update(over)
    return inv


def _issue(client, key, inv):
    """Merchant signs `inv`; buyer posts it for approval; returns the summary."""
    r = client.post("/request-invoice", json={"invoice": inv, "signature": sign_invoice(inv, key)})
    return r


def _approve(client, approval_id, key, cred_id, challenge, *, flags=0x05):
    return client.post(
        f"/approve/{approval_id}",
        json={"credentialId": cred_id, **_assertion_for(key, challenge, flags=flags)},
    )


# -- the happy path ---------------------------------------------------------- #
def test_signed_invoice_approved_by_both_roles(client):
    mkey = _merchant(client)
    ck, cid = _enroll(client, "child")
    pk, pid = _enroll(client, "parent")

    inv = _invoice()
    req = _issue(client, mkey, inv).json()
    assert set(req["required_roles"]) == {"child", "parent"}
    assert req["invoice"] == inv
    # The challenge the humans will sign is the invoice hash, not a self-asserted action.
    assert b64url_decode(req["challenge"]) == invoice_challenge(inv)

    ch = invoice_challenge(inv)
    r1 = _approve(client, req["id"], ck, cid, ch)
    assert r1.status_code == 200 and r1.json()["status"] == "pending"

    r2 = _approve(client, req["id"], pk, pid, ch)
    assert r2.status_code == 200
    out = r2.json()
    # Fully approved, but settlement is now a separate, explicit step (the
    # proxy's certified policy gates it, not full approval alone) — see /settle.
    assert out["status"] == "approved" and set(out["approved_roles"]) == {"child", "parent"}
    assert "receipt" not in out

    settled = client.post("/settle", json={"merchantId": inv["merchantId"], "amountCents": inv["totalCents"]}).json()
    assert settled["status"] == "settled"
    assert settled["receipt"]["nonce"] == inv["nonce"]


def test_solo_invoice_needs_only_child(client):
    mkey = _merchant(client)
    ck, cid = _enroll(client, "child")
    inv = _invoice(totalCents=500, nonce="urn:uuid:solo")  # <= $10
    req = _issue(client, mkey, inv).json()
    assert req["required_roles"] == ["child"]
    r = _approve(client, req["id"], ck, cid, invoice_challenge(inv))
    assert r.json()["status"] == "approved"  # child alone approves; /settle still separate
    assert client.post("/settle", json={"merchantId": inv["merchantId"], "amountCents": inv["totalCents"]}).json()["status"] == "settled"


# -- the refusals ------------------------------------------------------------ #
def test_untrusted_merchant_never_reaches_the_humans(client):
    mkey = Ed25519PrivateKey.generate()  # never registered into the trusted set
    r = _issue(client, mkey, _invoice())
    assert r.status_code == 400 and "not in the trusted set" in r.json()["detail"]


def test_tampered_invoice_rejected(client):
    mkey = _merchant(client)
    inv = _invoice()
    sig = sign_invoice(inv, mkey)
    inv["totalCents"] = 50_000  # raise the price after the merchant signed
    r = client.post("/request-invoice", json={"invoice": inv, "signature": sig})
    assert r.status_code == 400 and "signature" in r.json()["detail"]


def test_expired_invoice_rejected(client):
    mkey = _merchant(client)
    r = _issue(client, mkey, _invoice(exp=PAST))
    assert r.status_code == 400 and "expired" in r.json()["detail"]


def test_approval_bound_to_a_different_invoice_is_rejected(client):
    mkey = _merchant(client)
    ck, cid = _enroll(client, "child")
    _enroll(client, "parent")
    inv = _invoice()
    req = _issue(client, mkey, inv).json()
    # Sign the assertion over a *different* invoice's challenge.
    other = invoice_challenge(_invoice(totalCents=100, nonce="urn:uuid:other"))
    r = _approve(client, req["id"], ck, cid, other)
    assert r.status_code == 400 and "does not bind" in r.json()["detail"]


def test_role_not_required_is_rejected_for_solo_invoice(client):
    mkey = _merchant(client)
    _enroll(client, "child")
    pk, pid = _enroll(client, "parent")
    inv = _invoice(totalCents=500, nonce="urn:uuid:solo")  # only child required
    req = _issue(client, mkey, inv).json()
    r = _approve(client, req["id"], pk, pid, invoice_challenge(inv))
    assert r.status_code == 400 and "not required" in r.json()["detail"]


# --------------------------------------------------------------------------- #
# The audit trail: commitment intake closes the chain, /audit.json narrates it.
# --------------------------------------------------------------------------- #


def _settled_purchase(client):
    mkey = _merchant(client)
    ck, cid = _enroll(client, "child")
    pk, pid = _enroll(client, "parent")
    inv = _invoice()
    req = _issue(client, mkey, inv).json()
    ch = invoice_challenge(inv)
    _approve(client, req["id"], ck, cid, ch)
    out = _approve(client, req["id"], pk, pid, ch).json()
    assert out["status"] == "approved"
    settled = client.post("/settle", json={"merchantId": inv["merchantId"], "amountCents": inv["totalCents"]}).json()
    assert settled["status"] == "settled"
    return mkey, inv, req["id"], settled["receipt"]


def test_commitment_closes_the_chain_and_audit_renders_it(client):
    mkey, inv, approval_id, receipt = _settled_purchase(client)
    commitment = {
        "kind": "fulfillment", "merchantId": inv["merchantId"],
        "merchant": inv["merchant"], "nonce": inv["nonce"],
        "items": inv["items"], "paymentRef": receipt["paymentRef"],
        "etaMinutes": 45,
    }
    assert client.post(
        "/commitment",
        json={"commitment": commitment, "signature": sign_invoice(commitment, mkey)},
    ).status_code == 200

    [entry] = [e for e in client.get("/audit.json").json() if e["id"] == approval_id]
    assert entry["status"] == "fulfilled"
    assert entry["commitment"]["etaMinutes"] == 45
    assert set(entry["signatures"]) == {"merchant", "settlement", "fulfillment"}
    labels = " | ".join(ev["label"] for ev in entry["events"])
    assert "invoice received" in labels and "settled" in labels and "committed" in labels


def test_commitment_from_untrusted_merchant_refused(client):
    mkey, inv, approval_id, receipt = _settled_purchase(client)
    rogue = Ed25519PrivateKey.generate()
    commitment = {"kind": "fulfillment", "merchantId": inv["merchantId"],
                  "nonce": inv["nonce"], "items": inv["items"], "etaMinutes": 5}
    r = client.post(
        "/commitment",
        json={"commitment": commitment, "signature": sign_invoice(commitment, rogue)},
    )
    assert r.status_code == 400


def test_commitment_for_unknown_nonce_404s(client):
    mkey = _merchant(client)
    commitment = {"kind": "fulfillment", "merchantId": "pizza-1",
                  "nonce": "urn:uuid:nope", "etaMinutes": 5}
    r = client.post(
        "/commitment",
        json={"commitment": commitment, "signature": sign_invoice(commitment, mkey)},
    )
    assert r.status_code == 404

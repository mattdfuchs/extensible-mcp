# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""End-to-end exercise of the WebAuthn approval service without a browser,
including multi-party composition: trust a merchant, enroll a child and a
parent, request approval of an over-threshold merchant-signed invoice, and
confirm it is authorized only once *both* have signed — each biometric bound to
the invoice hash, so the assertion authorizes that one transaction and no other
— while a solo invoice needs only the child, and mismatched / unverified /
not-required approvals are rejected."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from extensible_mcp_vc.invoice import invoice_challenge
from extensible_mcp_vc.webauthn import b64url_decode

from .webauthn_fixtures import approve_invoice as _approve
from .webauthn_fixtures import enroll as _enroll
from .webauthn_fixtures import issue_invoice as _issue
from .webauthn_fixtures import load_approval_app, sample_invoice, trust_merchant

OVER = sample_invoice()  # $18 -> child + parent
SOLO = sample_invoice(totalCents=500, nonce="urn:uuid:solo")  # <= $10 -> child only


@pytest.fixture
def client():
    return TestClient(load_approval_app())


@pytest.fixture
def merchant(client):
    """The merchant key in the buyer's trusted set — nothing binds without it."""
    return trust_merchant(client)


def test_over_threshold_needs_both_child_and_parent(client, merchant):
    ck, cid = _enroll(client, "child")
    pk, pid = _enroll(client, "parent")
    req = _issue(client, merchant, OVER).json()
    assert set(req["required_roles"]) == {"child", "parent"}
    # The challenge the humans sign is the server's own hash of the invoice.
    assert b64url_decode(req["challenge"]) == invoice_challenge(OVER)
    ch = invoice_challenge(OVER)

    r1 = _approve(client, req["id"], ck, cid, ch)
    assert r1.status_code == 200
    assert r1.json()["status"] == "pending" and r1.json()["approved_roles"] == ["child"]

    r2 = _approve(client, req["id"], pk, pid, ch)
    assert r2.status_code == 200
    out = r2.json()
    assert out["status"] == "approved" and set(out["approved_roles"]) == {"child", "parent"}


def test_solo_needs_only_child(client, merchant):
    ck, cid = _enroll(client, "child")
    req = _issue(client, merchant, SOLO).json()
    assert req["required_roles"] == ["child"]
    assert _approve(client, req["id"], ck, cid, invoice_challenge(SOLO)).json()["status"] == "approved"


def test_role_not_required_is_rejected(client, merchant):
    _enroll(client, "child")
    pk, pid = _enroll(client, "parent")
    req = _issue(client, merchant, SOLO).json()  # only child needed
    r = _approve(client, req["id"], pk, pid, invoice_challenge(SOLO))
    assert r.status_code == 400 and "not required" in r.json()["detail"]


def test_assertion_bound_to_a_different_invoice_is_rejected(client, merchant):
    ck, cid = _enroll(client, "child")
    req = _issue(client, merchant, SOLO).json()
    attacker = sample_invoice(
        totalCents=5_000_000, merchant="Attacker LLC", nonce="urn:uuid:attacker"
    )
    # signed for the attacker's invoice, presented against this one
    r = _approve(client, req["id"], ck, cid, invoice_challenge(attacker))
    assert r.status_code == 400 and "does not bind" in r.json()["detail"]


def test_missing_user_verification_rejected(client, merchant):
    ck, cid = _enroll(client, "child")
    req = _issue(client, merchant, SOLO).json()
    # user present, not verified
    r = _approve(client, req["id"], ck, cid, invoice_challenge(SOLO), flags=0x01)
    assert r.status_code == 400 and "user-verified" in r.json()["detail"]


def test_unknown_credential_rejected(client, merchant):
    _enroll(client, "child")
    req = _issue(client, merchant, SOLO).json()
    stranger = ec.generate_private_key(ec.SECP256R1())
    r = _approve(client, req["id"], stranger, "nope", invoice_challenge(SOLO))
    assert r.status_code == 400 and "unknown credential" in r.json()["detail"]


def test_latest_pending_endpoint(client, merchant):
    _enroll(client, "child")
    _issue(client, merchant, OVER)
    j = client.get("/pending").json()
    assert j["invoice"] == OVER and j["status"] == "pending"
    assert set(j["remaining_roles"]) == {"child", "parent"}


# --------------------------------------------------------------------------- #
# The wallet-rail additions: retained assertions and the admin-signed
# enrollment VC (production binding).
# --------------------------------------------------------------------------- #


def test_assertion_retained_and_fetchable(client, merchant):
    ck, cid = _enroll(client, "child")
    pk, pid = _enroll(client, "parent")
    req = _issue(client, merchant, OVER).json()
    # not yet approved -> 404
    assert client.get(f"/assertion/{req['id']}/parent").status_code == 404
    ch = invoice_challenge(OVER)
    assert _approve(client, req["id"], ck, cid, ch).json()["status"] == "pending"
    r = _approve(client, req["id"], pk, pid, ch)
    assert r.status_code == 200 and r.json()["status"] == "approved"
    a = client.get(f"/assertion/{req['id']}/parent").json()
    assert a["credentialId"] == pid
    for field in ("authenticatorData", "clientDataJSON", "signature"):
        assert isinstance(a[field], str) and a[field]


def test_enrollment_vc_minted_and_admin_signed(client):
    # With the workspace admin key present, registration mints the
    # admin-signed enrollment VC binding credentialId -> (role, publicKey).
    import json as _json

    from extensible_mcp_vc.webauthn import jwk_string_to_public_key

    key, cred_id = _enroll(client, "parent")
    r = client.get(f"/enrollment/{cred_id}")
    if r.status_code == 404:
        pytest.skip("no workspace admin key in this checkout")
    e = r.json()
    claims = e["claims"]
    assert claims["sub"] == cred_id
    assert claims["iss"].startswith("did:web:")
    assert claims["vc"]["credentialSubject"]["role"] == "parent"
    # the enrolled publicKey is the registered passkey's P-256 key
    enrolled = jwk_string_to_public_key(
        claims["vc"]["credentialSubject"]["publicKey"]
    )
    assert enrolled.public_numbers() == key.public_key().public_numbers()
    # and the jws payload is exactly the claims (admin-signed envelope)
    import base64 as _b64

    payload = e["jws"].split(".")[1]
    decoded = _json.loads(_b64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert decoded == claims

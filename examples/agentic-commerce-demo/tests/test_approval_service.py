# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""End-to-end exercise of the WebAuthn approval service without a browser,
including multi-party composition: enroll a child and a parent, request an
over-threshold action, and confirm it is authorized only once *both* have
signed — each biometric bound to the exact action — while a solo action needs
only the child, and mismatched / unverified / not-required approvals are
rejected."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from extensible_mcp_vc.webauthn import b64url_encode, spend_challenge

from .webauthn_fixtures import assertion_for
from .webauthn_fixtures import attestation_object as _attestation_object

OVER = {"tool": "spend", "amountCents": 1500, "merchant": "acme"}  # > $10 -> child + parent
SOLO = {"tool": "spend", "amountCents": 500, "merchant": "acme"}  # <= $10 -> child only


def _load_app():
    path = Path(__file__).resolve().parents[1] / "examples" / "approval_service.py"
    spec = importlib.util.spec_from_file_location("approval_service", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.app


def _assertion(key, action, *, flags=0x05):
    """An assertion over the action's spend-challenge (the raw self-asserted path)."""
    challenge = spend_challenge(action["tool"], action["amountCents"], action["merchant"])
    return assertion_for(key, challenge, flags=flags)


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


def _approve(client, approval_id, key, cred_id, action, *, flags=0x05):
    return client.post(
        f"/approve/{approval_id}", json={"credentialId": cred_id, **_assertion(key, action, flags=flags)}
    )


def test_over_threshold_needs_both_child_and_parent(client):
    ck, cid = _enroll(client, "child")
    pk, pid = _enroll(client, "parent")
    req = client.post("/request", json={"action": OVER}).json()
    assert set(req["required_roles"]) == {"child", "parent"}

    r1 = _approve(client, req["id"], ck, cid, OVER)
    assert r1.status_code == 200
    assert r1.json()["status"] == "pending" and r1.json()["approved_roles"] == ["child"]

    r2 = _approve(client, req["id"], pk, pid, OVER)
    assert r2.status_code == 200
    out = r2.json()
    assert out["status"] == "approved" and set(out["approved_roles"]) == {"child", "parent"}


def test_solo_needs_only_child(client):
    ck, cid = _enroll(client, "child")
    req = client.post("/request", json={"action": SOLO}).json()
    assert req["required_roles"] == ["child"]
    assert _approve(client, req["id"], ck, cid, SOLO).json()["status"] == "approved"


def test_role_not_required_is_rejected(client):
    _enroll(client, "child")
    pk, pid = _enroll(client, "parent")
    req = client.post("/request", json={"action": SOLO}).json()  # only child needed
    r = _approve(client, req["id"], pk, pid, SOLO)
    assert r.status_code == 400 and "not required" in r.json()["detail"]


def test_assertion_bound_to_a_different_action_is_rejected(client):
    ck, cid = _enroll(client, "child")
    req = client.post("/request", json={"action": SOLO}).json()
    attacker = {"tool": "spend", "amountCents": 5_000_000, "merchant": "attacker"}
    r = _approve(client, req["id"], ck, cid, attacker)  # signed for the attacker action
    assert r.status_code == 400 and "does not bind" in r.json()["detail"]


def test_missing_user_verification_rejected(client):
    ck, cid = _enroll(client, "child")
    req = client.post("/request", json={"action": SOLO}).json()
    r = _approve(client, req["id"], ck, cid, SOLO, flags=0x01)  # user present, not verified
    assert r.status_code == 400 and "user-verified" in r.json()["detail"]


def test_unknown_credential_rejected(client):
    _enroll(client, "child")
    req = client.post("/request", json={"action": SOLO}).json()
    stranger = ec.generate_private_key(ec.SECP256R1())
    r = client.post(f"/approve/{req['id']}", json={"credentialId": "nope", **_assertion(stranger, SOLO)})
    assert r.status_code == 400 and "unknown credential" in r.json()["detail"]


def test_latest_pending_endpoint(client):
    _enroll(client, "child")
    client.post("/request", json={"action": OVER})
    j = client.get("/pending").json()
    assert j["action"] == OVER and j["status"] == "pending"
    assert set(j["remaining_roles"]) == {"child", "parent"}


# --------------------------------------------------------------------------- #
# The wallet-rail additions: roles override, retained assertions, and the
# admin-signed enrollment VC (production binding).
# --------------------------------------------------------------------------- #


def test_roles_override_narrows_required_roles(client):
    # On the wallet rail the requester's consent is the wallet-signed request
    # VC; only the approver signs here.
    _enroll(client, "parent")
    req = client.post(
        "/request", json={"action": OVER, "roles": ["parent"]}
    ).json()
    assert req["required_roles"] == ["parent"]


def test_assertion_retained_and_fetchable(client):
    key, cred_id = _enroll(client, "parent")
    req = client.post(
        "/request", json={"action": OVER, "roles": ["parent"]}
    ).json()
    # not yet approved -> 404
    assert client.get(f"/assertion/{req['id']}/parent").status_code == 404
    r = _approve(client, req["id"], key, cred_id, OVER)
    assert r.status_code == 200 and r.json()["status"] == "approved"
    a = client.get(f"/assertion/{req['id']}/parent").json()
    assert a["credentialId"] == cred_id
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

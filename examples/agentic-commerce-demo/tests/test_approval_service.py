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

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from extensible_mcp_vc.invoice import invoice_challenge
from extensible_mcp_vc.webauthn import b64url_decode, b64url_encode

from .webauthn_fixtures import approve_invoice as _approve
from .webauthn_fixtures import enroll as _enroll
from .webauthn_fixtures import issue_invoice as _issue
from .webauthn_fixtures import (
    attestation_object,
    load_approval_app,
    sample_invoice,
    sign_in,
    trust_merchant,
)

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


# -- enrollment is authenticated --------------------------------------------- #
#
# The service holds the admin's private key and signs "this passkey holds role
# X". Before the OAuth2 flow, the only gate was reaching the page, so anything
# on the network could enrol itself as parent and the admin would vouch for it.


class TestEnrollmentRequiresIdentity:
    def test_register_without_a_token_is_refused(self, client):
        key = ec.generate_private_key(ec.SECP256R1())
        r = client.post("/register", json={
            "attestationObject": b64url_encode(
                attestation_object(key.public_key(), b"cred-x")),
            "role": "parent"})
        assert r.status_code == 401
        assert "Bearer" in r.headers.get("WWW-Authenticate", "")

    def test_approve_without_a_token_is_refused(self, client):
        r = client.post("/approve/whatever", json={"credentialId": "x"})
        assert r.status_code == 401

    def test_a_forged_token_is_refused(self, client):
        key = ec.generate_private_key(ec.SECP256R1())
        for header in ("Bearer nonsense", "Bearer a.b.c", "Basic parent:parent", "parent"):
            r = client.post("/register", json={
                "attestationObject": b64url_encode(
                    attestation_object(key.public_key(), b"cred-x")),
            }, headers={"Authorization": header})
            assert r.status_code == 401, header

    def test_the_body_cannot_choose_the_role(self, client):
        """The point of the whole flow. Authenticated as the child, asking to be
        enrolled as the parent: the token decides and the body is ignored."""
        headers = sign_in(client, "child")
        key = ec.generate_private_key(ec.SECP256R1())
        r = client.post("/register", json={
            "attestationObject": b64url_encode(
                attestation_object(key.public_key(), b"cred-sneaky")),
            "role": "parent"}, headers=headers)
        assert r.status_code == 200
        assert r.json()["role"] == "child"

    def test_the_enrollment_credential_is_signed_for_the_token_s_role(self, client):
        """The admin's attestation must agree with the token, since that VC is
        what the policy reads."""
        import json as _json

        attested = TestClient(load_approval_app(with_admin_key=True))
        headers = sign_in(attested, "parent")
        key = ec.generate_private_key(ec.SECP256R1())
        r = attested.post("/register", json={
            "attestationObject": b64url_encode(
                attestation_object(key.public_key(), b"cred-parent")),
            "role": "child"}, headers=headers)
        assert r.status_code == 200 and r.json()["role"] == "parent"
        assert r.json()["adminAttested"] is True
        enrolled = attested.get(f"/enrollment/{r.json()['credentialId']}").json()
        payload = enrolled["jws"].split(".")[1]
        claims = _json.loads(
            base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        assert claims["vc"]["credentialSubject"]["role"] == "parent"


class TestTheFlowItself:
    def test_an_unregistered_redirect_uri_is_refused(self, client):
        """An authorization server that redirects wherever the request says is
        an open redirect, and hands codes to whoever asked."""
        from extensible_mcp_vc.oauth import CLIENT_ID, pkce_challenge

        r = client.get("/authorize", params={
            "response_type": "code", "client_id": CLIENT_ID,
            "redirect_uri": "https://evil.example/collect",
            "code_challenge": pkce_challenge("v" * 48),
            "code_challenge_method": "S256"})
        assert r.status_code == 400

    def test_a_wrong_password_does_not_yield_a_code(self, client):
        from extensible_mcp_vc.oauth import pkce_challenge

        r = client.post("/authorize", data={
            "username": "parent", "password": "wrong", "redirect_uri": "/",
            "code_challenge": pkce_challenge("v" * 48), "state": "s"},
            follow_redirects=False)
        assert r.status_code == 401
        assert "location" not in {k.lower() for k in r.headers}

    def test_a_code_cannot_be_redeemed_twice(self, client):
        import secrets
        from urllib.parse import parse_qs, urlparse

        from extensible_mcp_vc.oauth import CLIENT_ID, pkce_challenge

        verifier = secrets.token_urlsafe(48)
        password = next(
            u.password for u in client.app.state.users.users if u.role == "child")
        r = client.post("/authorize", data={
            "username": "child", "password": password, "redirect_uri": "/",
            "code_challenge": pkce_challenge(verifier), "state": "s"},
            follow_redirects=False)
        code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
        form = {"grant_type": "authorization_code", "code": code,
                "code_verifier": verifier, "redirect_uri": "/", "client_id": CLIENT_ID}
        assert client.post("/token", data=form).status_code == 200
        assert client.post("/token", data=form).status_code == 400

    def test_pkce_binds_the_exchange_to_the_client_that_started_it(self, client):
        """Without the verifier check, an intercepted code is enough."""
        import secrets
        from urllib.parse import parse_qs, urlparse

        from extensible_mcp_vc.oauth import CLIENT_ID, pkce_challenge

        verifier = secrets.token_urlsafe(48)
        password = next(
            u.password for u in client.app.state.users.users if u.role == "child")
        r = client.post("/authorize", data={
            "username": "child", "password": password, "redirect_uri": "/",
            "code_challenge": pkce_challenge(verifier), "state": "s"},
            follow_redirects=False)
        code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
        r = client.post("/token", data={
            "grant_type": "authorization_code", "code": code,
            "code_verifier": secrets.token_urlsafe(48),  # not the one used
            "redirect_uri": "/", "client_id": CLIENT_ID})
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"

    def test_me_reports_the_authenticated_identity(self, client):
        r = client.get("/me", headers=sign_in(client, "parent"))
        assert r.status_code == 200
        assert r.json() == {"sub": "parent", "role": "parent"}

    def test_passwords_are_not_the_usernames(self, client):
        """A fixed pair would make the login a speed bump: two guesses."""
        for user in client.app.state.users.users:
            assert user.password != user.username
            assert len(user.password) >= 12

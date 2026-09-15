# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the wallet FastAPI service."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from household_identity.common import did as did_mod
from household_identity.common import jws, keys, vc
from household_identity.wallet.server import create_app


def _approver(approve: bool):
    async def _fn(_message: str) -> bool:
        return approve

    return _fn


@pytest.fixture
def parent_key():
    return keys.generate_keypair()


@pytest.fixture
def kid_key():
    return keys.generate_keypair()


class TestInfoEndpoint:
    def test_returns_label_and_did(self, kid_key):
        app = create_app(private_key=kid_key, label="kid", approve=_approver(True))
        client = TestClient(app)
        r = client.get("/")
        assert r.status_code == 200
        body = r.json()
        assert body["label"] == "kid"
        assert body["did"] == did_mod.did_key_from_public_key(kid_key)


class TestSignRequest:
    def test_approved_returns_signed_vc(self, kid_key):
        app = create_app(private_key=kid_key, label="kid", approve=_approver(True))
        client = TestClient(app)
        r = client.post(
            "/sign/request",
            json={"request_type": "spend", "details": {"amount": 15.0}},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["issuer"] == did_mod.did_key_from_public_key(kid_key)
        # Verifies against the wallet's public key.
        claims = jws.verify_jwt(body["token"], key=kid_key.public_key())
        assert claims["jti"] == body["jti"]
        cs = claims["vc"]["credentialSubject"]
        assert cs["requests"]["type"] == "spend"
        assert cs["requests"]["amount"] == 15.0

    def test_denied_returns_403(self, kid_key):
        app = create_app(private_key=kid_key, label="kid", approve=_approver(False))
        client = TestClient(app)
        r = client.post(
            "/sign/request",
            json={"request_type": "spend", "details": {"amount": 15.0}},
        )
        assert r.status_code == 403


class TestSignAuthorization:
    def _sign_a_request(self, kid_key):
        app = create_app(private_key=kid_key, label="kid", approve=_approver(True))
        client = TestClient(app)
        r = client.post(
            "/sign/request",
            json={"request_type": "spend", "details": {"amount": 15.0}},
        )
        return r.json()

    def test_approved_binds_to_request(self, kid_key, parent_key):
        request = self._sign_a_request(kid_key)
        app = create_app(
            private_key=parent_key, label="parent", approve=_approver(True)
        )
        client = TestClient(app)
        r = client.post(
            "/sign/authorization",
            json={"request_token": request["token"], "scope": {"max_amount": 20.0}},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["issuer"] == did_mod.did_key_from_public_key(parent_key)
        assert body["bound_request_jti"] == request["jti"]
        assert body["bound_request_hash"] == vc.hash_request(request["token"])
        claims = jws.verify_jwt(body["token"], key=parent_key.public_key())
        cs = claims["vc"]["credentialSubject"]
        assert cs["authorizes_request"] == request["jti"]
        assert cs["request_hash"] == body["bound_request_hash"]
        assert cs["scope"] == {"max_amount": 20.0}

    def test_denied_returns_403(self, kid_key, parent_key):
        request = self._sign_a_request(kid_key)
        app = create_app(
            private_key=parent_key, label="parent", approve=_approver(False)
        )
        client = TestClient(app)
        r = client.post(
            "/sign/authorization",
            json={"request_token": request["token"], "scope": {}},
        )
        assert r.status_code == 403

    def test_malformed_request_token_returns_400(self, parent_key):
        app = create_app(
            private_key=parent_key, label="parent", approve=_approver(True)
        )
        client = TestClient(app)
        r = client.post(
            "/sign/authorization",
            json={"request_token": "not.a.jwt.too.many.parts", "scope": {}},
        )
        assert r.status_code == 400

    def test_authorization_does_not_carry_to_other_request(
        self, kid_key, parent_key
    ):
        """The binding hash differs across requests, so one authorization
        cannot be re-attached to a different request."""
        first = self._sign_a_request(kid_key)
        second = self._sign_a_request(kid_key)
        assert first["token"] != second["token"]
        app = create_app(
            private_key=parent_key, label="parent", approve=_approver(True)
        )
        client = TestClient(app)
        auth = client.post(
            "/sign/authorization",
            json={"request_token": first["token"], "scope": {}},
        ).json()
        assert auth["bound_request_hash"] == vc.hash_request(first["token"])
        assert auth["bound_request_hash"] != vc.hash_request(second["token"])


class TestMembershipAttachment:
    def test_membership_absent_when_not_configured(self, kid_key):
        app = create_app(private_key=kid_key, label="kid", approve=_approver(True))
        client = TestClient(app)
        info = client.get("/").json()
        assert info["has_membership"] is False
        req = client.post(
            "/sign/request",
            json={"request_type": "spend", "details": {}},
        ).json()
        assert req["membership"] is None

    def test_membership_attached_to_request_response(self, kid_key):
        app = create_app(
            private_key=kid_key,
            label="kid",
            approve=_approver(True),
            membership_token="opaque.jwt.token",
        )
        client = TestClient(app)
        assert client.get("/").json()["has_membership"] is True
        req = client.post(
            "/sign/request",
            json={"request_type": "spend", "details": {}},
        ).json()
        assert req["membership"] == "opaque.jwt.token"

    def test_membership_attached_to_authorization_response(
        self, kid_key, parent_key
    ):
        kid_app = create_app(
            private_key=kid_key, label="kid", approve=_approver(True)
        )
        request = TestClient(kid_app).post(
            "/sign/request",
            json={"request_type": "spend", "details": {}},
        ).json()
        parent_app = create_app(
            private_key=parent_key,
            label="parent",
            approve=_approver(True),
            membership_token="parent.membership.jwt",
        )
        auth = TestClient(parent_app).post(
            "/sign/authorization",
            json={"request_token": request["token"], "scope": {}},
        ).json()
        assert auth["membership"] == "parent.membership.jwt"


def _build_capture_app() -> tuple[FastAPI, list[dict]]:
    """Tiny FastAPI app that records every POST body it receives."""
    received: list[dict] = []
    app = FastAPI(title="capture")

    @app.post("/cb")
    async def cb(body: dict):
        received.append(body)
        return {"ok": True}

    return app, received


async def _wait_for(received: list[dict], timeout: float = 2.0) -> dict:
    """Poll the capture list until something lands or the deadline expires."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if received:
            return received[0]
        await asyncio.sleep(0.01)
    raise AssertionError("callback was never fired within timeout")


class TestAsyncApprovalCallback:
    async def test_sign_request_returns_202_then_calls_back_with_bundle(
        self, kid_key
    ):
        capture_app, received = _build_capture_app()
        capture_transport = httpx.ASGITransport(app=capture_app)
        wallet_app = create_app(
            private_key=kid_key,
            label="kid",
            approve=_approver(True),
            callback_transport=capture_transport,
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=wallet_app),
            base_url="http://wallet",
        ) as client:
            r = await client.post(
                "/sign/request",
                json={
                    "request_type": "spend",
                    "details": {"amount": 15.0},
                    "callback_url": "http://capture/cb",
                },
            )
        assert r.status_code == 202
        body = r.json()
        assert "approval_id" in body and body["status"] == "pending"
        captured = await _wait_for(received)
        assert captured["approval_id"] == body["approval_id"]
        assert captured["status"] == "approved"
        # Token verifies against the wallet key
        claims = jws.verify_jwt(captured["token"], key=kid_key.public_key())
        cs = claims["vc"]["credentialSubject"]
        assert cs["requests"]["type"] == "spend"
        assert cs["requests"]["amount"] == 15.0

    async def test_sign_authorization_callback_carries_binding(
        self, kid_key, parent_key
    ):
        # Step 1: kid signs a request synchronously
        kid_app = create_app(
            private_key=kid_key, label="kid", approve=_approver(True)
        )
        request = TestClient(kid_app).post(
            "/sign/request",
            json={"request_type": "spend", "details": {"amount": 15.0}},
        ).json()
        # Step 2: parent signs the authorization asynchronously via callback
        capture_app, received = _build_capture_app()
        parent_app = create_app(
            private_key=parent_key,
            label="parent",
            approve=_approver(True),
            callback_transport=httpx.ASGITransport(app=capture_app),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=parent_app),
            base_url="http://wallet",
        ) as client:
            r = await client.post(
                "/sign/authorization",
                json={
                    "request_token": request["token"],
                    "scope": {"max_amount": 20.0},
                    "callback_url": "http://capture/cb",
                },
            )
        assert r.status_code == 202
        captured = await _wait_for(received)
        assert captured["status"] == "approved"
        assert captured["bound_request_jti"] == request["jti"]
        assert captured["bound_request_hash"] == vc.hash_request(request["token"])

    async def test_denial_fires_callback_with_denied_status(self, kid_key):
        capture_app, received = _build_capture_app()
        wallet_app = create_app(
            private_key=kid_key,
            label="kid",
            approve=_approver(False),
            callback_transport=httpx.ASGITransport(app=capture_app),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=wallet_app),
            base_url="http://wallet",
        ) as client:
            r = await client.post(
                "/sign/request",
                json={
                    "request_type": "spend",
                    "details": {},
                    "callback_url": "http://capture/cb",
                },
            )
        assert r.status_code == 202
        captured = await _wait_for(received)
        assert captured["status"] == "denied"
        assert "token" not in captured

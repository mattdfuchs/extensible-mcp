# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the VC meta-tools.

The tests bind an httpx client directly to a household-identity wallet's
ASGI app — no sockets, no ports, but the full FastAPI stack including the
real signing primitives.
"""

from __future__ import annotations

import httpx
import pytest
from household_identity.common import jws, keys
from household_identity.did_server.membership import make_membership_vc
from household_identity.wallet.server import create_app

from extensible_mcp_vc.meta_tools import (
    _async_post_sign,
    request_action_vc,
    request_authorization_vc,
)


def _auto_approve(approve: bool):
    async def _fn(_message: str) -> bool:
        return approve

    return _fn


@pytest.fixture
def admin_key():
    return keys.generate_keypair()


@pytest.fixture
def kid_key():
    return keys.generate_keypair()


@pytest.fixture
def kid_membership_token(admin_key, kid_key):
    from household_identity.common.did import did_key_from_public_key

    payload = make_membership_vc(
        admin_did="did:web:family.example.com",
        member_did=did_key_from_public_key(kid_key),
        role="child",
    )
    return jws.sign_jwt(payload, key=admin_key, kid="did:web:family.example.com")


def _client_for(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://wallet"
    )


class TestRequestActionVc:
    async def test_approved_returns_bundle_with_membership(
        self, kid_key, kid_membership_token
    ):
        app = create_app(
            private_key=kid_key,
            label="kid",
            approve=_auto_approve(True),
            membership_token=kid_membership_token,
        )
        async with _client_for(app) as client:
            bundle = await request_action_vc(client, "spend", {"amount": 15.0})
        assert bundle["membership"] == kid_membership_token
        # Verify the returned token is genuine: signature checks out
        claims = jws.verify_jwt(bundle["token"], key=kid_key.public_key())
        assert claims["vc"]["credentialSubject"]["requests"]["amount"] == 15.0

    async def test_declined_returns_error_object(self, kid_key):
        app = create_app(
            private_key=kid_key, label="kid", approve=_auto_approve(False)
        )
        async with _client_for(app) as client:
            out = await request_action_vc(client, "spend", {"amount": 15.0})
        assert "declined" in out["error"]


class TestRequestAuthorizationVc:
    async def test_approved_binds_to_request(
        self, admin_key, kid_key, kid_membership_token
    ):
        from household_identity.common.did import did_key_from_public_key

        parent_key = keys.generate_keypair()
        parent_membership_payload = make_membership_vc(
            admin_did="did:web:family.example.com",
            member_did=did_key_from_public_key(parent_key),
            role="parent",
        )
        parent_membership = jws.sign_jwt(
            parent_membership_payload,
            key=admin_key,
            kid="did:web:family.example.com",
        )
        kid_app = create_app(
            private_key=kid_key,
            label="kid",
            approve=_auto_approve(True),
            membership_token=kid_membership_token,
        )
        parent_app = create_app(
            private_key=parent_key,
            label="parent",
            approve=_auto_approve(True),
            membership_token=parent_membership,
        )
        async with _client_for(kid_app) as kid_client:
            req_bundle = await request_action_vc(
                kid_client, "spend", {"amount": 15.0}
            )
        async with _client_for(parent_app) as parent_client:
            auth_bundle = await request_authorization_vc(
                parent_client, req_bundle, {"max_amount": 20.0}
            )
        assert auth_bundle["membership"] == parent_membership
        claims = jws.verify_jwt(
            auth_bundle["token"], key=parent_key.public_key()
        )
        cs = claims["vc"]["credentialSubject"]
        assert cs["authorizes_request"]  # carries the request jti
        assert cs["scope"] == {"max_amount": 20.0}

    async def test_missing_token_in_request_returns_error(self, kid_key):
        app = create_app(
            private_key=kid_key, label="kid", approve=_auto_approve(True)
        )
        async with _client_for(app) as client:
            out = await request_authorization_vc(client, {"membership": "x"}, {})
        assert "token" in out["error"]

    async def test_json_string_request_is_parsed(
        self, admin_key, kid_key, kid_membership_token
    ):
        import json as _json

        from household_identity.common.did import did_key_from_public_key

        parent_key = keys.generate_keypair()
        parent_membership_payload = make_membership_vc(
            admin_did="did:web:family.example.com",
            member_did=did_key_from_public_key(parent_key),
            role="parent",
        )
        parent_membership = jws.sign_jwt(
            parent_membership_payload,
            key=admin_key,
            kid="did:web:family.example.com",
        )
        kid_app = create_app(
            private_key=kid_key,
            label="kid",
            approve=_auto_approve(True),
            membership_token=kid_membership_token,
        )
        parent_app = create_app(
            private_key=parent_key,
            label="parent",
            approve=_auto_approve(True),
            membership_token=parent_membership,
        )
        async with _client_for(kid_app) as kid_client:
            req_bundle = await request_action_vc(
                kid_client, "spend", {"amount": 15.0}
            )
        async with _client_for(parent_app) as parent_client:
            # Pass the bundle as a JSON string, the way some LLMs hand it back
            auth_bundle = await request_authorization_vc(
                parent_client, _json.dumps(req_bundle), {"max_amount": 20.0}
            )
        assert "error" not in auth_bundle
        assert auth_bundle["membership"] == parent_membership


class TestUnreachableWallet:
    async def test_connection_error_surfaces_as_error_object(self):
        # http://127.0.0.1:1 — port 1 is reserved/closed; httpx raises ConnectError
        async with httpx.AsyncClient(base_url="http://127.0.0.1:1") as client:
            out = await request_action_vc(client, "spend", {})
        assert out["error"].startswith("could not reach originator wallet")


def _build_proxy_receiver(pending: dict):
    """Tiny ASGI app mirroring the proxy's /vc-callback/{id} endpoint.

    Standing in for the real custom_route on the running FastMCP server.
    Same contract: pop the future from ``pending``, set its result with the
    body.
    """
    from fastapi import FastAPI

    app = FastAPI(title="proxy-receiver")

    @app.post("/vc-callback/{approval_id}")
    async def cb(approval_id: str, body: dict):
        future = pending.pop(approval_id, None)
        if future is None or future.done():
            return {"ok": False, "reason": "unknown"}
        future.set_result(body)
        return {"ok": True}

    return app


class TestAsyncCallbackFlow:
    async def test_kid_async_approval_round_trips_via_callback(
        self, kid_key, kid_membership_token
    ):
        pending: dict = {}
        receiver = _build_proxy_receiver(pending)
        wallet_app = create_app(
            private_key=kid_key,
            label="kid",
            approve=_auto_approve(True),
            membership_token=kid_membership_token,
            # When the wallet POSTs its callback, route through the receiver app
            callback_transport=httpx.ASGITransport(app=receiver),
        )
        async with _client_for(wallet_app) as client:
            bundle = await _async_post_sign(
                client=client,
                path="/sign/request",
                body={"request_type": "spend", "details": {"amount": 15.0}},
                actor="originator wallet",
                pending=pending,
                callback_base_url="http://receiver",
                callback_timeout_seconds=5.0,
            )
        assert "error" not in bundle
        assert bundle["membership"] == kid_membership_token
        claims = jws.verify_jwt(bundle["token"], key=kid_key.public_key())
        assert claims["vc"]["credentialSubject"]["requests"]["amount"] == 15.0
        assert pending == {}  # cleaned up after resolve

    async def test_denied_async_approval_surfaces_as_error(self, kid_key):
        pending: dict = {}
        receiver = _build_proxy_receiver(pending)
        wallet_app = create_app(
            private_key=kid_key,
            label="kid",
            approve=_auto_approve(False),
            callback_transport=httpx.ASGITransport(app=receiver),
        )
        async with _client_for(wallet_app) as client:
            out = await _async_post_sign(
                client=client,
                path="/sign/request",
                body={"request_type": "spend", "details": {}},
                actor="originator wallet",
                pending=pending,
                callback_base_url="http://receiver",
                callback_timeout_seconds=5.0,
            )
        assert "declined" in out["error"]
        assert pending == {}

    async def test_timeout_returns_error_and_cleans_up(self, kid_key):
        """An approval that never gets pushed back should hit the timeout and
        be removed from the pending dict so it doesn't leak."""
        import asyncio

        # An approve_fn that hangs forever — wallet will never POST a callback
        async def _hangs(_msg: str) -> bool:
            await asyncio.Event().wait()  # blocks forever
            return True

        pending: dict = {}
        receiver = _build_proxy_receiver(pending)
        wallet_app = create_app(
            private_key=kid_key,
            label="kid",
            approve=_hangs,
            callback_transport=httpx.ASGITransport(app=receiver),
        )
        async with _client_for(wallet_app) as client:
            out = await _async_post_sign(
                client=client,
                path="/sign/request",
                body={"request_type": "spend", "details": {}},
                actor="originator wallet",
                pending=pending,
                callback_base_url="http://receiver",
                callback_timeout_seconds=0.2,
            )
        assert "did not respond within" in out["error"]
        assert pending == {}

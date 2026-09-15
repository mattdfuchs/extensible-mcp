# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests for VCCallFilter — full chain + every failure mode."""

from __future__ import annotations

import pytest
from extensible_mcp import CallRequest
from household_identity.common import did as did_mod
from household_identity.common import jws, keys, vc
from household_identity.did_server.document import make_did_document
from household_identity.did_server.membership import make_membership_vc

from extensible_mcp_vc.config import VCConfig
from extensible_mcp_vc.vc_filter import VCCallFilter

ADMIN_DID = "did:web:family.example.com"


@pytest.fixture
def admin_key():
    return keys.generate_keypair()


@pytest.fixture
def admin_doc(admin_key):
    return make_did_document(did=ADMIN_DID, key=admin_key)


@pytest.fixture
def kid_key():
    return keys.generate_keypair()


@pytest.fixture
def parent_key():
    return keys.generate_keypair()


@pytest.fixture
def kid_did(kid_key):
    return did_mod.did_key_from_public_key(kid_key)


@pytest.fixture
def parent_did(parent_key):
    return did_mod.did_key_from_public_key(parent_key)


def _sign_membership(admin_key, admin_did, member_did, role, ttl_seconds=365 * 86400):
    payload = make_membership_vc(
        admin_did=admin_did, member_did=member_did, role=role,
        ttl_seconds=ttl_seconds,
    )
    return jws.sign_jwt(payload, key=admin_key, kid=admin_did)


def _sign_request(kid_key, kid_did, membership, ttl_seconds=600, details=None):
    payload = vc.make_action_request(
        issuer_did=kid_did,
        request_type="spend",
        details=details or {"amount": 15.0},
        ttl_seconds=ttl_seconds,
    )
    token = jws.sign_jwt(payload, key=kid_key, kid=kid_did)
    return {"token": token, "membership": membership}, payload["jti"]


def _sign_auth(parent_key, parent_did, membership, request_token, request_jti, ttl_seconds=14400, scope=None):
    payload = vc.make_action_authorization(
        issuer_did=parent_did,
        request_jti=request_jti,
        request_hash=vc.hash_request(request_token),
        scope=scope or {},
        ttl_seconds=ttl_seconds,
    )
    token = jws.sign_jwt(payload, key=parent_key, kid=parent_did)
    return {"token": token, "membership": membership}


@pytest.fixture
def config(admin_doc):
    return VCConfig(
        originator_wallet_url="http://kid.invalid",
        approver_wallet_url="http://parent.invalid",
        trusted_admin_dids=[ADMIN_DID],
        gated_tools=["payments__*"],
        preresolved_did_documents={ADMIN_DID: admin_doc},
    )


@pytest.fixture
def filter_(config):
    return VCCallFilter(config)


@pytest.fixture
def kid_membership(admin_key, kid_did):
    return _sign_membership(admin_key, ADMIN_DID, kid_did, "child")


@pytest.fixture
def parent_membership(admin_key, parent_did):
    return _sign_membership(admin_key, ADMIN_DID, parent_did, "parent")


@pytest.fixture
def good_bundles(kid_key, kid_did, kid_membership, parent_key, parent_did, parent_membership):
    req, req_jti = _sign_request(kid_key, kid_did, kid_membership)
    auth = _sign_auth(parent_key, parent_did, parent_membership, req["token"], req_jti)
    return req, auth


def _payments_call(req=None, auth=None, extras=None):
    args = dict(extras or {"amount": 15.0, "vendor": "pizza"})
    if req is not None:
        args["vc_request"] = req
    if auth is not None:
        args["vc_authorization"] = auth
    return CallRequest(
        tool_name="payments__spend", arguments=args, server_name="payments"
    )


class TestPassthrough:
    async def test_non_gated_tool_unmodified(self, filter_):
        request = CallRequest(
            tool_name="github__create_issue",
            arguments={"title": "x"},
            server_name="github",
        )
        result = await filter_.check(request)
        assert result.allowed
        assert result.arguments == {"title": "x"}


class TestHappyPath:
    async def test_full_chain_passes_and_strips_vcs(self, filter_, good_bundles):
        req, auth = good_bundles
        result = await filter_.check(_payments_call(req=req, auth=auth))
        assert result.allowed, result.reason
        # VCs are stripped; the verified marker is left so downstream
        # policy filters can read it. In gated mode both flags are True.
        assert result.arguments == {
            "amount": 15.0,
            "vendor": "pizza",
            "_verified_vcs": {"request": True, "authorization": True},
        }

    async def test_json_string_bundles_are_accepted(self, filter_, good_bundles):
        import json as _json

        req, auth = good_bundles
        result = await filter_.check(
            _payments_call(req=_json.dumps(req), auth=_json.dumps(auth))
        )
        assert result.allowed, result.reason
        assert result.arguments == {
            "amount": 15.0,
            "vendor": "pizza",
            "_verified_vcs": {"request": True, "authorization": True},
        }


class TestMalformedBundles:
    async def test_missing_request_bundle(self, filter_, good_bundles):
        _, auth = good_bundles
        result = await filter_.check(_payments_call(auth=auth))
        assert not result.allowed
        assert "vc_request" in result.reason

    async def test_missing_authorization_bundle(self, filter_, good_bundles):
        req, _ = good_bundles
        result = await filter_.check(_payments_call(req=req))
        assert not result.allowed
        assert "vc_authorization" in result.reason

    async def test_request_bundle_without_token_field(self, filter_, good_bundles):
        _, auth = good_bundles
        result = await filter_.check(
            _payments_call(req={"membership": "x"}, auth=auth)
        )
        assert not result.allowed
        assert "vc_request" in result.reason


class TestSignatureVerification:
    async def test_tampered_request_payload_rejected(
        self, filter_, good_bundles
    ):
        req, auth = good_bundles
        # Flip a bit in the signature segment
        token = req["token"]
        head, payload, sig = token.split(".")
        bad_sig = sig[:-1] + ("A" if sig[-1] != "A" else "B")
        bad_req = {"token": f"{head}.{payload}.{bad_sig}", "membership": req["membership"]}
        result = await filter_.check(_payments_call(req=bad_req, auth=auth))
        assert not result.allowed
        assert "request VC signature" in result.reason

    async def test_tampered_authorization_rejected(
        self, filter_, good_bundles
    ):
        req, auth = good_bundles
        token = auth["token"]
        head, payload, sig = token.split(".")
        bad_sig = sig[:-1] + ("A" if sig[-1] != "A" else "B")
        bad_auth = {"token": f"{head}.{payload}.{bad_sig}", "membership": auth["membership"]}
        result = await filter_.check(_payments_call(req=req, auth=bad_auth))
        assert not result.allowed
        assert "authorization VC signature" in result.reason


class TestBinding:
    async def test_authorization_for_different_request_rejected(
        self, filter_, kid_key, kid_did, kid_membership,
        parent_key, parent_did, parent_membership,
    ):
        req_a, _ = _sign_request(kid_key, kid_did, kid_membership, details={"amount": 5.0})
        req_b, req_b_jti = _sign_request(kid_key, kid_did, kid_membership, details={"amount": 5000.0})
        # Authorization is bound to request_b, but call presents request_a
        auth_for_b = _sign_auth(
            parent_key, parent_did, parent_membership,
            req_b["token"], req_b_jti,
        )
        result = await filter_.check(_payments_call(req=req_a, auth=auth_for_b))
        assert not result.allowed
        # Mismatch hits jti first since it's checked first
        assert "jti" in result.reason or "content hash" in result.reason


class TestTemporal:
    async def test_expired_request_rejected(
        self, config, kid_key, kid_did, kid_membership,
        parent_key, parent_did, parent_membership,
    ):
        # Request VC with very short ttl; advance the filter's clock past exp.
        req, req_jti = _sign_request(kid_key, kid_did, kid_membership, ttl_seconds=10)
        auth = _sign_auth(
            parent_key, parent_did, parent_membership, req["token"], req_jti,
            ttl_seconds=86400,
        )
        # Find the actual exp from the freshly signed request and jump past it.
        import json, base64
        payload_b64 = req["token"].split(".")[1]
        pad = "=" * (-len(payload_b64) % 4)
        exp = json.loads(base64.urlsafe_b64decode(payload_b64 + pad))["exp"]
        future = exp + 1
        filter_ = VCCallFilter(config, clock=lambda: future)
        result = await filter_.check(_payments_call(req=req, auth=auth))
        assert not result.allowed
        assert "request VC outside its validity window" in result.reason


class TestMembership:
    async def test_missing_membership_rejected(
        self, filter_, kid_key, kid_did,
        parent_key, parent_did, parent_membership,
    ):
        # Build request without attaching kid's membership
        req, req_jti = _sign_request(kid_key, kid_did, membership="")
        auth = _sign_auth(parent_key, parent_did, parent_membership, req["token"], req_jti)
        result = await filter_.check(_payments_call(req=req, auth=auth))
        assert not result.allowed
        assert "missing membership" in result.reason

    async def test_untrusted_admin_rejected(
        self, config, kid_key, kid_did, parent_key, parent_did,
    ):
        # Mint memberships from an untrusted admin
        rogue_key = keys.generate_keypair()
        rogue_did = "did:web:rogue.example.com"
        rogue_doc = make_did_document(did=rogue_did, key=rogue_key)
        # Preload the rogue admin doc so resolution would succeed
        config.preresolved_did_documents[rogue_did] = rogue_doc
        kid_membership = _sign_membership(rogue_key, rogue_did, kid_did, "child")
        parent_membership = _sign_membership(rogue_key, rogue_did, parent_did, "parent")
        req, req_jti = _sign_request(kid_key, kid_did, kid_membership)
        auth = _sign_auth(parent_key, parent_did, parent_membership, req["token"], req_jti)
        filter_ = VCCallFilter(config)
        result = await filter_.check(_payments_call(req=req, auth=auth))
        assert not result.allowed
        assert "untrusted admin" in result.reason

    async def test_membership_subject_mismatch_rejected(
        self, filter_, kid_key, kid_did, admin_key,
        parent_key, parent_did, parent_membership,
    ):
        # Issue kid's membership for a DIFFERENT key (a swapped membership)
        other_key = keys.generate_keypair()
        other_did = did_mod.did_key_from_public_key(other_key)
        wrong_membership = _sign_membership(admin_key, ADMIN_DID, other_did, "child")
        req, req_jti = _sign_request(kid_key, kid_did, wrong_membership)
        auth = _sign_auth(parent_key, parent_did, parent_membership, req["token"], req_jti)
        result = await filter_.check(_payments_call(req=req, auth=auth))
        assert not result.allowed
        assert "does not match signer" in result.reason


class TestOptionalAuthorizationMode:
    """When a tool is in optional_authorization_tools (and not gated_tools)
    the request VC is required but the auth VC is verified-if-present.
    The filter writes a _verified_vcs marker so downstream policy filters
    can enforce conditional rules."""

    @pytest.fixture
    def opt_config(self, admin_doc):
        return VCConfig(
            originator_wallet_url="http://kid.invalid",
            approver_wallet_url="http://parent.invalid",
            trusted_admin_dids=[ADMIN_DID],
            gated_tools=[],
            # Only the order tool is policy-controlled; list_stores stays
            # unguarded so the LLM can discover what's on the menu.
            optional_authorization_tools=["pizza__order_pizza"],
            preresolved_did_documents={ADMIN_DID: admin_doc},
        )

    @pytest.fixture
    def opt_filter(self, opt_config):
        return VCCallFilter(opt_config)

    def _pizza_call(self, *, req=None, auth=None, extras=None):
        args = dict(
            extras
            or {
                "pizza_type": "small cheese",
                "store": "Dominos",
                "address": "123 Main St",
                "quantity": 1,
                "total": 9.0,
            }
        )
        if req is not None:
            args["vc_request"] = req
        if auth is not None:
            args["vc_authorization"] = auth
        return CallRequest(
            tool_name="pizza__order_pizza", arguments=args, server_name="pizza"
        )

    async def test_request_only_passes_and_marks_authorization_unverified(
        self, opt_filter, good_bundles
    ):
        req, _ = good_bundles
        result = await opt_filter.check(self._pizza_call(req=req))
        assert result.allowed, result.reason
        assert result.arguments["_verified_vcs"] == {
            "request": True,
            "authorization": False,
        }
        # Original args still present, VCs stripped
        assert result.arguments["total"] == 9.0
        assert "vc_request" not in result.arguments
        assert "vc_authorization" not in result.arguments

    async def test_both_vcs_pass_and_mark_authorization_verified(
        self, opt_filter, good_bundles
    ):
        req, auth = good_bundles
        result = await opt_filter.check(self._pizza_call(req=req, auth=auth))
        assert result.allowed, result.reason
        assert result.arguments["_verified_vcs"] == {
            "request": True,
            "authorization": True,
        }

    async def test_missing_request_bundle_is_still_rejected(
        self, opt_filter, good_bundles
    ):
        _, auth = good_bundles
        result = await opt_filter.check(self._pizza_call(auth=auth))
        assert not result.allowed
        assert "vc_request" in result.reason

    async def test_tampered_auth_when_present_is_rejected(
        self, opt_filter, good_bundles
    ):
        req, auth = good_bundles
        # Flip a bit in the auth VC's signature segment
        head, payload, sig = auth["token"].split(".")
        bad_sig = sig[:-1] + ("A" if sig[-1] != "A" else "B")
        bad_auth = {
            "token": f"{head}.{payload}.{bad_sig}",
            "membership": auth["membership"],
        }
        result = await opt_filter.check(self._pizza_call(req=req, auth=bad_auth))
        assert not result.allowed
        assert "signature invalid" in result.reason

    async def test_ungated_tool_passes_unchanged(self, opt_filter):
        # A tool not in either list isn't touched
        request = CallRequest(
            tool_name="pizza__list_stores", arguments={}, server_name="pizza"
        )
        result = await opt_filter.check(request)
        assert result.allowed
        assert "_verified_vcs" not in result.arguments

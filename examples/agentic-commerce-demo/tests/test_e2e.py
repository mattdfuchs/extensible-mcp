# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""End-to-end: meta-tool output round-trips through the VC filter.

This is the most load-bearing test in the package. It uses real wallets,
real memberships, real signing — runs the meta-tools to obtain bundles,
then feeds them back into the VCCallFilter exactly as the LLM would, and
asserts the call is allowed.
"""

from __future__ import annotations

import httpx
import pytest
from extensible_mcp import CallRequest
from household_identity.common import did as did_mod
from household_identity.common import jws, keys
from household_identity.did_server.document import make_did_document
from household_identity.did_server.membership import make_membership_vc
from household_identity.wallet.server import create_app

from extensible_mcp_vc.config import VCConfig
from extensible_mcp_vc.meta_tools import (
    request_action_vc,
    request_authorization_vc,
)
from extensible_mcp_vc.vc_filter import VCCallFilter

ADMIN_DID = "did:web:family.example.com"


async def _auto_approve(_message: str) -> bool:
    return True


def _sign_membership(*, admin_key, member_did, role):
    payload = make_membership_vc(
        admin_did=ADMIN_DID, member_did=member_did, role=role
    )
    return jws.sign_jwt(payload, key=admin_key, kid=ADMIN_DID)


@pytest.fixture
def admin_key():
    return keys.generate_keypair()


@pytest.fixture
def admin_doc(admin_key):
    return make_did_document(did=ADMIN_DID, key=admin_key)


def _client_for(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://wallet"
    )


class TestE2E:
    async def test_wallet_to_filter_round_trip(self, admin_key, admin_doc):
        kid_key = keys.generate_keypair()
        parent_key = keys.generate_keypair()
        kid_did = did_mod.did_key_from_public_key(kid_key)
        parent_did = did_mod.did_key_from_public_key(parent_key)

        kid_membership = _sign_membership(
            admin_key=admin_key, member_did=kid_did, role="child"
        )
        parent_membership = _sign_membership(
            admin_key=admin_key, member_did=parent_did, role="parent"
        )

        kid_app = create_app(
            private_key=kid_key,
            label="kid",
            approve=_auto_approve,
            membership_token=kid_membership,
        )
        parent_app = create_app(
            private_key=parent_key,
            label="parent",
            approve=_auto_approve,
            membership_token=parent_membership,
        )

        # 1. LLM asks kid wallet to sign an action request.
        async with _client_for(kid_app) as kid_client:
            request_bundle = await request_action_vc(
                kid_client, "spend", {"amount": 15.0, "vendor": "pizza"}
            )
        assert "error" not in request_bundle

        # 2. LLM asks parent wallet to sign an authorization bound to it.
        async with _client_for(parent_app) as parent_client:
            auth_bundle = await request_authorization_vc(
                parent_client, request_bundle, {"max_amount": 20.0}
            )
        assert "error" not in auth_bundle

        # 3. LLM calls the gated payments tool, passing both bundles.
        vc_config = VCConfig(
            originator_wallet_url="http://kid.invalid",
            approver_wallet_url="http://parent.invalid",
            trusted_admin_dids=[ADMIN_DID],
            gated_tools=["payments__*"],
            preresolved_did_documents={ADMIN_DID: admin_doc},
        )
        filter_ = VCCallFilter(vc_config)
        call = CallRequest(
            tool_name="payments__spend",
            arguments={
                "amount": 15.0,
                "vendor": "pizza",
                "vc_request": request_bundle,
                "vc_authorization": auth_bundle,
            },
            server_name="payments",
        )
        result = await filter_.check(call)
        assert result.allowed, result.reason
        # VCs are stripped; the verified marker is left for downstream
        # policy filters. In gated mode both flags are True.
        assert result.arguments == {
            "amount": 15.0,
            "vendor": "pizza",
            "_verified_vcs": {"request": True, "authorization": True},
        }

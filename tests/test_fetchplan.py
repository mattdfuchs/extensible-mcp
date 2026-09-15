# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests for the fetch-plan executor, including an end-to-end slice that
assembles the family_spend input via the real fetchplan.json and feeds it
straight into the WASM policy engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from extensible_mcp.fetchplan import (
    FetchContext,
    FetchError,
    FetchExecutor,
)
from extensible_mcp.wasm_policy import OpaWasmPolicy
from tests import vc_helpers as vc

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "family_spend"
PLAN = json.loads((FIXTURE_DIR / "fetchplan.json").read_text())
WASM = FIXTURE_DIR / "policy.wasm"
ALLOW = "policybundle/examples/family_spend/allow"


@pytest.fixture(scope="module")
def key():
    return vc.new_key()


def _context(key, *, amount: int, with_auth: bool) -> FetchContext:
    """Build a fetch context for a family-spend call.

    Memberships are wallet-sourced (looked up by subject DID); the request and
    (optionally) authorization VCs are call-sourced in the envelope.
    """
    args = {"amountCents": amount, "merchant": "acme"}
    req = vc.request_vc(args=args, key=key)
    envelope = {"tool": "send", "arguments": args, "requestVC": req}
    if with_auth:
        envelope["authorizationVC"] = vc.authorization_vc(request_jws=req["jws"], key=key)
    else:
        # Present-but-inert authorization (solo path never reads its claims).
        envelope["authorizationVC"] = {
            "jws": req["jws"],
            "claims": {"jti": "r1", "iss": vc.PARENT_DID, "requestHash": "0" * 64,
                       "nbf": 0, "exp": 9999999999},
        }

    memberships = {
        vc.KID_DID: vc.membership(sub=vc.KID_DID, role="kid", key=key),
        vc.PARENT_DID: vc.membership(sub=vc.PARENT_DID, role="parent", key=key),
    }

    async def wallet_lookup(subject: str):
        return memberships.get(subject)

    return FetchContext(
        envelope=envelope,
        config={"trustRootDID": vc.TRUST_DID, "trustRootJwk": vc.public_jwk(key)},
        now=100,
        wallet=wallet_lookup,
    )


async def test_assembles_all_plan_fields(key):
    ctx = _context(key, amount=500, with_auth=False)
    assembled = await FetchExecutor().assemble(PLAN, ctx)
    # Every field the plan declares is present and closed.
    expected = {e["field"] for e in PLAN["entries"]}
    assert set(assembled) == expected
    # wallet lookup wired the kid's membership by the request's iss
    assert assembled["requesterMembership"]["claims"]["role"] == "kid"
    assert assembled["approverMembership"]["claims"]["role"] == "parent"


async def test_assembled_solo_input_allows_in_engine(key):
    """The whole point: assemble → evaluate → allow, end to end."""
    ctx = _context(key, amount=500, with_auth=False)
    assembled = await FetchExecutor().assemble(PLAN, ctx)
    policy = OpaWasmPolicy(WASM)
    result = policy.query(assembled, ALLOW)
    assert result[0]["result"] is True


async def test_assembled_full_chain_input_allows_in_engine(key):
    ctx = _context(key, amount=5000, with_auth=True)
    assembled = await FetchExecutor().assemble(PLAN, ctx)
    policy = OpaWasmPolicy(WASM)
    assert policy.query(assembled, ALLOW)[0]["result"] is True


async def test_missing_call_field_fails_closed(key):
    ctx = _context(key, amount=500, with_auth=False)
    del ctx.envelope["requestVC"]
    with pytest.raises(FetchError, match="requestVC"):
        await FetchExecutor().assemble(PLAN, ctx)


async def test_missing_config_fails_closed(key):
    ctx = _context(key, amount=500, with_auth=False)
    del ctx.config["trustRootJwk"]
    with pytest.raises(FetchError, match="trustRootJwk"):
        await FetchExecutor().assemble(PLAN, ctx)


async def test_wallet_miss_fails_closed(key):
    ctx = _context(key, amount=500, with_auth=False)

    async def empty_wallet(subject: str):
        return None

    ctx.wallet = empty_wallet
    with pytest.raises(FetchError, match="no credential for subject"):
        await FetchExecutor().assemble(PLAN, ctx)


async def test_input_substitution_navigates_assembled_fields(key):
    """The wallet subject is drawn from requestVC.claims.iss via $input."""
    ctx = _context(key, amount=500, with_auth=False)
    seen = []

    async def recording_wallet(subject: str):
        seen.append(subject)
        return vc.membership(sub=subject, role="kid", key=key)

    ctx.wallet = recording_wallet
    await FetchExecutor().assemble(PLAN, ctx)
    # requesterMembership subject = requestVC.claims.iss = KID_DID
    assert vc.KID_DID in seen and vc.PARENT_DID in seen

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Shadow harness on *real* traffic: primary = the hand-coded ``VCCallFilter``,
shadow = the supplied-bundle ``VCPolicyFilter`` running the shipped
``family_spend_prod`` bundle. One call, both engines.

This is the real point of shadow mode — measure where the replacement diverges
from the incumbent on traffic the incumbent accepts. The bundle fixture lives in
the proxy package's own test fixtures; the test skips cleanly if it isn't
present.

The divergences this surfaces are genuine migration blockers, asserted here so
they are regression-guarded and can't be silently "fixed" by a traffic change
that masks them (regression-guarded on purpose)."""

from __future__ import annotations

from pathlib import Path

import pytest
from extensible_mcp import CallRequest
from household_identity.common import did as did_mod
from household_identity.common import jws, keys, vc
from household_identity.did_server.document import make_did_document
from household_identity.did_server.membership import make_membership_vc

from extensible_mcp_vc.config import VCConfig
from extensible_mcp_vc.shadow import ShadowCallFilter
from extensible_mcp_vc.vc_filter import VCCallFilter

# The supplied production bundle lives in the proxy package's own fixtures.
_BUNDLE_DIR = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / "fixtures"
    / "family_spend_prod"
)

pytestmark = pytest.mark.skipif(
    not (_BUNDLE_DIR / "policy.wasm").exists(),
    reason=f"family_spend_prod bundle not found at {_BUNDLE_DIR}",
)

ADMIN_DID = "did:web:family.example.com"


def _now() -> int:
    # household-identity stamps nbf/exp from the real clock at VC creation,
    # so the filters must read a live clock too — a value frozen at import
    # sits *before* the nbf of any VC minted after a second boundary.
    import time

    return int(time.time())


def _shadow_filter(admin_key):
    """A real VCPolicyFilter over the prod bundle, configured for the fork's
    on-the-wire field names (``vc_request`` / ``vc_authorization``) and trusting
    the same admin as the primary."""
    from extensible_mcp.bundle import PolicyBundle
    from extensible_mcp.didweb import DidWebResolver
    from extensible_mcp.wallet_bundle import WalletBundleAdapter
    from extensible_mcp.wasm_filter import VCPolicyFilter

    bundle = PolicyBundle.load(_BUNDLE_DIR, name="family_spend_prod")
    resolver = DidWebResolver(
        [ADMIN_DID], preresolved={ADMIN_DID: keys.public_jwk(admin_key)}
    )
    adapter = WalletBundleAdapter(
        request_field="vc_request", authorization_field="vc_authorization"
    )
    return VCPolicyFilter(
        bundle,
        adapter=adapter,
        resolver=resolver,
        trusted_admin_dids=[ADMIN_DID],
        clock=_now,
    )


def _membership(admin_key, member_did, role):
    payload = make_membership_vc(
        admin_did=ADMIN_DID, member_did=member_did, role=role, ttl_seconds=365 * 86400
    )
    return jws.sign_jwt(payload, key=admin_key, kid=ADMIN_DID)


def _request(kid_key, kid_did, membership, details):
    payload = vc.make_action_request(
        issuer_did=kid_did, request_type="spend", details=details, ttl_seconds=600
    )
    token = jws.sign_jwt(payload, key=kid_key, kid=kid_did)
    return {"token": token, "membership": membership}, payload["jti"]


def _auth(parent_key, parent_did, membership, request_token, request_jti):
    payload = vc.make_action_authorization(
        issuer_did=parent_did,
        request_jti=request_jti,
        request_hash=vc.hash_request(request_token),
        scope={},
        ttl_seconds=14400,
    )
    token = jws.sign_jwt(payload, key=parent_key, kid=parent_did)
    return {"token": token, "membership": membership}


@pytest.fixture
def wired():
    admin_key = keys.generate_keypair()
    kid_key = keys.generate_keypair()
    parent_key = keys.generate_keypair()
    kid_did = did_mod.did_key_from_public_key(kid_key)
    parent_did = did_mod.did_key_from_public_key(parent_key)

    config = VCConfig(
        originator_wallet_url="http://kid.invalid",
        approver_wallet_url="http://parent.invalid",
        trusted_admin_dids=[ADMIN_DID],
        gated_tools=["payments__*"],
        preresolved_did_documents={
            ADMIN_DID: make_did_document(did=ADMIN_DID, key=admin_key)
        },
    )
    primary = VCCallFilter(config, clock=_now)
    shadow = _shadow_filter(admin_key)
    harness = ShadowCallFilter(primary, shadow)

    return {
        "harness": harness,
        "admin_key": admin_key,
        "kid_key": kid_key, "kid_did": kid_did,
        "parent_key": parent_key, "parent_did": parent_did,
    }


def _full_chain_call(wired, details):
    kid_m = _membership(wired["admin_key"], wired["kid_did"], "child")
    parent_m = _membership(wired["admin_key"], wired["parent_did"], "parent")
    req, jti = _request(wired["kid_key"], wired["kid_did"], kid_m, details)
    auth = _auth(wired["parent_key"], wired["parent_did"], parent_m, req["token"], jti)
    args = dict(details)
    args["vc_request"] = req
    args["vc_authorization"] = auth
    return CallRequest(
        tool_name="payments__spend", arguments=args, server_name="payments"
    )


async def test_primary_accepts_but_policy_diverges_on_current_traffic(wired):
    """A call the incumbent VCCallFilter fully accepts is *denied* by the
    production policy — surfacing the two migration blockers below."""
    harness = wired["harness"]
    call = _full_chain_call(wired, {"amount": 15.0, "vendor": "pizza"})

    result = await harness.check(call)

    # The incumbent accepts it (valid chain, signatures, binding, membership).
    assert result.allowed is True

    (rec,) = harness.records
    # The replacement would deny — this is the divergence shadow mode exists for.
    assert rec.direction == "new-deny"
    # It is NOT a red flag (allow->deny is triaged), but it IS a blocker to triage.
    assert rec.is_red_flag is False


async def test_role_vocabulary_now_aligned(wired):
    """The requester-role blocker is **resolved**. The policy was aligned to the
    role the wallets actually issue — ``"child"`` — so the membership role now
    satisfies the role check and no longer diverges. (What still diverges on
    current traffic is the merchant/vendor binding, next.)"""
    harness = wired["harness"]
    call = _full_chain_call(wired, {"amount": 15.0, "vendor": "pizza"})
    await harness.check(call)
    (rec,) = harness.records
    assert "role" not in rec.buckets


async def test_blocker_missing_merchant_is_invisible_in_the_reason_set(wired):
    """Current request VCs carry ``vendor``, not the ``merchant`` the policy
    binds. With the field absent on *both* sides the binding condition is
    undefined, so it fails the tier without firing an id — the vocabulary
    blocker surfaces as a denial attributed to *other* checks, not as a
    ``call-binding`` bucket. Documented in the migration review: triage
    must not read the bucket histogram as exhaustive."""
    harness = wired["harness"]
    call = _full_chain_call(wired, {"amount": 15.0, "vendor": "pizza"})
    await harness.check(call)
    (rec,) = harness.records
    assert rec.direction == "new-deny"
    assert "call-binding" not in rec.buckets  # absent-field failures fire no id


async def test_replay_divergence_names_call_binding(wired):
    """The tightening the fork lacks: a validly signed request replayed
    with different call arguments. The incumbent verifies signatures only and
    allows; the policy binds the signed merchant to the actual call and
    denies, with the binding named in the buckets. Roles are aligned
    (``"child"``) here to isolate the binding divergence."""
    kid_m = _membership(wired["admin_key"], wired["kid_did"], "child")
    parent_m = _membership(wired["admin_key"], wired["parent_did"], "parent")
    req, jti = _request(
        wired["kid_key"], wired["kid_did"], kid_m,
        {"amount": 5.0, "merchant": "pizza"},
    )
    auth = _auth(wired["parent_key"], wired["parent_did"], parent_m, req["token"], jti)
    args = {
        "amount": 5.0,
        "merchant": "sushi",  # not what was signed
        "vc_request": req,
        "vc_authorization": auth,
    }
    call = CallRequest(
        tool_name="payments__spend", arguments=args, server_name="payments"
    )
    harness = wired["harness"]
    result = await harness.check(call)

    assert result.allowed is True  # the incumbent is content-blind
    (rec,) = harness.records
    assert rec.direction == "new-deny"
    assert "call-binding" in rec.buckets


async def test_no_new_allow_or_shadow_error(wired):
    """Whatever else diverges, the replacement must never be *weaker* than the
    incumbent, nor fault — those are the hard red flags."""
    harness = wired["harness"]
    call = _full_chain_call(wired, {"amount": 15.0, "vendor": "pizza"})
    await harness.check(call)
    assert harness.summary().clean is True  # no new-allow, no shadow-error

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The token/evidence seam: the session's account must be the member whose
key signed the request, on the admin's word.

``cel_family_spend_bound`` is the teaching bundle plus that one condition.
The cases here are the four the spec names: bound, mismatched, the DID
case where equality suffices, and no principal at all.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.types import CallRequest, Principal
from extensible_mcp.wasm_filter import WasmPolicyFilter
from tests import vc_helpers as vc

FIXTURE = Path(__file__).parent / "fixtures" / "cel_family_spend_bound"
IDP = "https://idp.example/realms/household"
KID_ACCOUNT = "kid-a3f1"


@pytest.fixture(scope="module")
def key():
    return vc.new_key()


@pytest.fixture(scope="module")
def bundle():
    return PolicyBundle.load(FIXTURE, name="cel_family_spend_bound")


def _membership(sub: str, role: str, key, accounts=None) -> dict:
    m = vc.membership(sub=sub, role=role, key=key)
    if accounts is not None:
        m["claims"]["accounts"] = accounts
    return m


def _filter(bundle, key, *, kid_accounts) -> WasmPolicyFilter:
    table = {
        vc.KID_DID: _membership(vc.KID_DID, "kid", key, kid_accounts),
        vc.PARENT_DID: _membership(vc.PARENT_DID, "parent", key),
    }

    async def lookup(subject: str):
        return table.get(subject)

    return WasmPolicyFilter(
        bundle,
        config={"trustRootDID": vc.TRUST_DID, "trustRootJwk": vc.public_jwk(key)},
        wallet_lookup=lookup,
        clock=lambda: 100,
    )


def _call(key, principal: Principal | None) -> CallRequest:
    args = {"amountCents": 500, "merchant": "acme"}  # solo tier: the kid alone
    req = vc.request_vc(args=args, key=key)
    # The teaching bundle's manifest requires authorizationVC on every call
    # (tests/test_cel_policy.py sends the same placeholder for a solo call).
    placeholder_auth = {
        "jws": req["jws"],
        "claims": {"jti": "r1", "iss": vc.PARENT_DID, "requestHash": "0" * 64,
                   "nbf": 0, "exp": 9999999999},
    }
    return CallRequest(
        tool_name="payments__send",
        arguments={**args, "requestVC": req, "authorizationVC": placeholder_auth},
        server_name="payments",
        principal=principal,
    )


KID_SESSION = Principal(sub=KID_ACCOUNT, iss=IDP, roles=frozenset({"child"}))
PARENT_SESSION = Principal(sub="parent-77", iss=IDP, roles=frozenset({"parent"}))
BOUND = [{"idp": IDP, "account": KID_ACCOUNT}]


async def test_the_bound_session_is_allowed(bundle, key):
    result = await _filter(bundle, key, kid_accounts=BOUND).check(_call(key, KID_SESSION))
    assert result.allowed, result.reason


async def test_another_members_session_is_refused_with_the_sentence(bundle, key):
    """The parent's session submits a request the kid's wallet signed. Every
    signature verifies; the binding is what fails, and the denial says so."""
    result = await _filter(bundle, key, kid_accounts=BOUND).check(_call(key, PARENT_SESSION))
    assert not result.allowed
    assert "session's account is not bound to the member whose key signed" in result.reason


async def test_the_same_account_at_another_provider_is_not_the_same_person(bundle, key):
    elsewhere = dataclasses.replace(KID_SESSION, iss="https://other-idp.example")
    result = await _filter(bundle, key, kid_accounts=BOUND).check(_call(key, elsewhere))
    assert not result.allowed


async def test_a_membership_with_no_accounts_binds_no_session(bundle, key):
    """Older credentials carry no accounts; under a principal they bind nobody,
    which is the fail-closed reading until the admin re-issues."""
    result = await _filter(bundle, key, kid_accounts=None).check(_call(key, KID_SESSION))
    assert not result.allowed
    # A rendered denial, not a fault: the quantifier is guarded by `has`, so
    # an absent list is a failed check with its sentence, never a CEL raise.
    assert "session's account is not bound to the member whose key signed" in result.reason


async def test_the_did_case_is_a_plain_equality(bundle, key):
    """An issuer whose subjects are DIDs (the 0.5 own-issuer shape) needs no
    accounts list: the token's sub is the membership's sub."""
    did_session = Principal(sub=vc.KID_DID, iss="https://approval.example", roles=frozenset())
    result = await _filter(bundle, key, kid_accounts=None).check(_call(key, did_session))
    assert result.allowed, result.reason


async def test_no_principal_leaves_the_condition_vacuous(bundle, key):
    """Stdio, or an HTTP deployment that opted out: no token, no caller
    fields, the check holds. Requiring a principal is require_principal's
    job, not the bundle's."""
    result = await _filter(bundle, key, kid_accounts=None).check(_call(key, None))
    assert result.allowed, result.reason


def test_the_caller_fields_are_not_credentials(bundle):
    assert bundle.credential_fields() == ["requestVC", "authorizationVC"]
    assert {e["field"] for e in bundle.fetchplan["entries"] if e["source"]["kind"] == "caller"} == {
        "callerIdp", "callerAccount",
    }

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Single-use evidence: one signed approval authorizes one call.

The policy is a pure function of the evidence and the call, so it decides the
same way every time the same pair is submitted. These tests cover the guard
against that, including against the real ``family_spend_prod`` bundle: the
same VC pair that legitimately buys one $15 pizza must not buy three.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.didweb import DidWebResolver
from extensible_mcp.replay import SingleUseEvidenceFilter, wallet_bundle_jti
from extensible_mcp.types import CallFilterResult, CallRequest
from extensible_mcp.wallet_bundle import WalletBundleAdapter
from extensible_mcp.wasm_filter import VCPolicyFilter
from tests import vc_helpers as vc

ADMIN_DID = "did:web:admin.example"
PROD_DIR = Path(__file__).parent / "fixtures" / "family_spend_prod"


# -- a stub inner filter, for the guard's own behaviour ---------------------- #

class _Recorder:
    """Allows everything, counting how many calls got through."""

    def __init__(self, allow: bool = True) -> None:
        self.allow = allow
        self.seen = 0

    async def check(self, request: CallRequest) -> CallFilterResult:
        self.seen += 1
        return CallFilterResult(
            allowed=self.allow,
            reason="" if self.allow else "inner said no",
            tool_name=request.tool_name,
            arguments={k: v for k, v in request.arguments.items() if k != "requestVC"},
        )


def _bundle(jti: str, *, exp: int | None = 9999999999) -> dict:
    claims: dict = {"iss": "did:key:z1", "jti": jti}
    if exp is not None:
        claims["exp"] = exp
    return {"token": vc.sign(claims, vc.new_key()), "membership": "m"}


def _call(bundle, *, amount: float = 15.0) -> CallRequest:
    return CallRequest(
        tool_name="payments__spend",
        arguments={"amount": amount, "merchant": "acme", "requestVC": bundle},
        server_name="payments",
    )


class TestGuard:
    async def test_second_use_of_the_same_credential_is_refused(self):
        inner = _Recorder()
        f = SingleUseEvidenceFilter(inner)
        b = _bundle("urn:req1")

        first = await f.check(_call(b))
        assert first.allowed is True

        second = await f.check(_call(b))
        assert second.allowed is False
        assert "already been used" in second.reason
        # The inner filter is not even consulted for a spent credential.
        assert inner.seen == 1

    async def test_a_different_credential_still_passes(self):
        f = SingleUseEvidenceFilter(_Recorder())
        assert (await f.check(_call(_bundle("urn:req1")))).allowed is True
        assert (await f.check(_call(_bundle("urn:req2")))).allowed is True

    async def test_a_denied_call_does_not_spend_the_credential(self):
        """Otherwise an LLM that gets the amount wrong once would burn the
        human's approval and send them back to the wallet."""
        inner = _Recorder(allow=False)
        f = SingleUseEvidenceFilter(inner)
        b = _bundle("urn:req1")

        refused = await f.check(_call(b, amount=999.0))
        assert refused.allowed is False
        assert refused.reason == "inner said no"

        # Same credential, now on a call the policy accepts.
        inner.allow = True
        assert (await f.check(_call(b))).allowed is True

    async def test_a_spent_entry_is_forgotten_once_the_credential_expires(self):
        """Past its own expiry the policy refuses the credential anyway, so
        remembering it buys nothing and the store must not grow forever."""
        now = [1000.0]
        f = SingleUseEvidenceFilter(_Recorder(), clock=lambda: now[0])
        b = _bundle("urn:req1", exp=1500)

        assert (await f.check(_call(b))).allowed is True
        assert (await f.check(_call(b))).allowed is False
        now[0] = 1600.0
        f._prune(now[0])
        assert f._spent == {}

    async def test_a_credential_with_no_jti_is_refused_not_admitted(self):
        """Unspendable evidence must not be treated as fresh evidence."""
        f = SingleUseEvidenceFilter(_Recorder())
        result = await f.check(_call(_bundle_without_jti()))
        assert result.allowed is False
        assert "jti" in result.reason

    async def test_malformed_evidence_keeps_the_policy_s_own_message(self):
        """The guard must not shadow a better explanation."""
        f = SingleUseEvidenceFilter(_Recorder(allow=False))
        result = await f.check(_call({"token": "not-a-jws"}))
        assert result.allowed is False
        assert result.reason == "inner said no"

    async def test_no_credential_field_present_is_the_policy_s_business(self):
        inner = _Recorder(allow=False)
        f = SingleUseEvidenceFilter(inner)
        result = await f.check(
            CallRequest(
                tool_name="payments__spend",
                arguments={"amount": 15.0, "merchant": "acme"},
                server_name="payments",
            )
        )
        assert result.allowed is False and inner.seen == 1

    async def test_refuses_rather_than_evicting_when_the_store_is_full(self):
        """Evicting a live entry to make room would let a replay through."""
        f = SingleUseEvidenceFilter(_Recorder(), max_entries=2)
        assert (await f.check(_call(_bundle("urn:a")))).allowed is True
        assert (await f.check(_call(_bundle("urn:b")))).allowed is True
        full = await f.check(_call(_bundle("urn:c")))
        assert full.allowed is False
        assert "cannot currently guarantee" in full.reason

    async def test_a_denial_carries_no_evidence_forward(self):
        f = SingleUseEvidenceFilter(_Recorder())
        b = _bundle("urn:req1")
        await f.check(_call(b))
        second = await f.check(_call(b))
        assert "requestVC" not in second.arguments
        assert second.arguments == {"amount": 15.0, "merchant": "acme"}

    async def test_stringified_bundle_is_keyed_the_same(self):
        """Some MCP client paths stringify object-typed tool results, so the
        same credential can arrive as JSON text."""
        f = SingleUseEvidenceFilter(_Recorder())
        b = _bundle("urn:req1")
        assert (await f.check(_call(b))).allowed is True
        assert (await f.check(_call(json.dumps(b)))).allowed is False


def _bundle_without_jti() -> dict:
    return {"token": vc.sign({"iss": "did:key:z1", "exp": 9999999999}, vc.new_key())}


class TestJtiExtraction:
    def test_reads_the_jti_from_a_bundle(self):
        assert wallet_bundle_jti(_bundle("urn:x")) == "urn:x"

    @pytest.mark.parametrize(
        "value", [None, 5, "plain string", {}, {"token": "not-a-jws"}, {"nope": 1}]
    )
    def test_unreadable_values_yield_nothing(self, value):
        assert wallet_bundle_jti(value) is None


# -- against the real bundle ------------------------------------------------- #

@pytest.fixture(scope="module")
def keys():
    return {"kid": vc.new_key(), "parent": vc.new_key(), "admin": vc.new_key()}


def _membership(keys, who, role):
    return vc.sign(
        {"iss": ADMIN_DID, "sub": vc.did_key(keys[who]), "nbf": 0, "exp": 9999999999,
         "vc": {"credentialSubject": {"role": role}}},
        keys["admin"],
    )


def _signed_pair(keys, *, amount: float, jti: str):
    kid_did = vc.did_key(keys["kid"])
    req_token = vc.sign(
        {"iss": kid_did, "nbf": 0, "exp": 9999999999, "jti": jti,
         "vc": {"credentialSubject": {
             "id": kid_did,
             "requests": {"type": "spend", "amount": amount, "merchant": "acme"}}}},
        keys["kid"],
    )
    parent_did = vc.did_key(keys["parent"])
    auth_token = vc.sign(
        {"iss": parent_did, "nbf": 0, "exp": 9999999999, "jti": f"{jti}-auth",
         "vc": {"credentialSubject": {
             "id": parent_did, "authorizes_request": jti,
             "request_hash": "sha256:" + hashlib.sha256(req_token.encode()).hexdigest()}}},
        keys["parent"],
    )
    return (
        {"token": req_token, "membership": _membership(keys, "kid", "child")},
        {"token": auth_token, "membership": _membership(keys, "parent", "parent")},
    )


@pytest.fixture
def guarded_prod_filter(keys):
    bundle = PolicyBundle.load(PROD_DIR, name="family_spend_prod")
    resolver = DidWebResolver(
        [ADMIN_DID], preresolved={ADMIN_DID: keys["admin"].as_dict(private=False)}
    )
    return SingleUseEvidenceFilter(
        VCPolicyFilter(
            bundle,
            adapter=WalletBundleAdapter(),
            resolver=resolver,
            trusted_admin_dids=[ADMIN_DID],
            clock=lambda: 100,
        ),
        clock=lambda: 100,
    )


async def test_one_approval_buys_one_pizza(guarded_prod_filter, keys):
    """The regression, against the bundle the demo actually runs: a $15
    request VC plus its parental authorization went through as many times as
    it was submitted -- one approval, unlimited spend."""
    req, auth = _signed_pair(keys, amount=15.00, jti="urn:req1")

    def call():
        return CallRequest(
            tool_name="payments__spend",
            arguments={"amount": 15.00, "merchant": "acme",
                       "requestVC": dict(req), "authorizationVC": dict(auth)},
            server_name="payments",
        )

    first = await guarded_prod_filter.check(call())
    assert first.allowed is True, first.reason
    assert first.arguments == {"amount": 15.00, "merchant": "acme"}

    for _ in range(2):
        again = await guarded_prod_filter.check(call())
        assert again.allowed is False
        assert "already been used" in again.reason
        assert "requestVC" not in again.arguments


async def test_a_fresh_approval_still_works(guarded_prod_filter, keys):
    """The guard must not break the normal case: a second, separately signed
    approval is a different jti and goes through."""
    for jti in ("urn:reqA", "urn:reqB"):
        req, auth = _signed_pair(keys, amount=15.00, jti=jti)
        result = await guarded_prod_filter.check(
            CallRequest(
                tool_name="payments__spend",
                arguments={"amount": 15.00, "merchant": "acme",
                           "requestVC": req, "authorizationVC": auth},
                server_name="payments",
            )
        )
        assert result.allowed is True, result.reason

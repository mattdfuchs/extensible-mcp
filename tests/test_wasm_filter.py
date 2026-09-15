# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests for WasmPolicyFilter: the full call path on a real compiled bundle —
split envelope, assemble, evaluate, strip credential args / deny."""

from __future__ import annotations

from pathlib import Path

import pytest

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.types import CallRequest
from extensible_mcp.wasm_filter import WasmPolicyFilter
from tests import vc_helpers as vc

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "family_spend"


@pytest.fixture(scope="module")
def key():
    return vc.new_key()


@pytest.fixture
def bundle():
    return PolicyBundle.load(FIXTURE_DIR, name="family_spend")


def _memberships(key):
    table = {
        vc.KID_DID: vc.membership(sub=vc.KID_DID, role="kid", key=key),
        vc.PARENT_DID: vc.membership(sub=vc.PARENT_DID, role="parent", key=key),
    }

    async def lookup(subject: str):
        return table.get(subject)

    return lookup


def _filter(bundle, key, **overrides):
    kwargs = dict(
        config={"trustRootDID": vc.TRUST_DID, "trustRootJwk": vc.public_jwk(key)},
        wallet_lookup=_memberships(key),
        clock=lambda: 100,
    )
    kwargs.update(overrides)
    return WasmPolicyFilter(bundle, **kwargs)


def _call(key, *, amount: int, with_auth: bool, tool="payments__send") -> CallRequest:
    """A tool call as the LLM would make it: native args plus the credential
    fields supplied as top-level arguments (as the augmenter surfaces them)."""
    args = {"amountCents": amount, "merchant": "acme"}
    req = vc.request_vc(args=args, key=key)
    arguments = {**args, "requestVC": req}
    if with_auth:
        arguments["authorizationVC"] = vc.authorization_vc(request_jws=req["jws"], key=key)
    else:
        arguments["authorizationVC"] = {
            "jws": req["jws"],
            "claims": {"jti": "r1", "iss": vc.PARENT_DID, "requestHash": "0" * 64,
                       "nbf": 0, "exp": 9999999999},
        }
    return CallRequest(tool_name=tool, arguments=arguments, server_name="payments")


def test_bundle_exposes_credential_fields(bundle):
    # call fields include tool/arguments + the two VC bundles
    assert set(bundle.credential_fields()) == {"requestVC", "authorizationVC"}
    assert bundle.allow_entrypoint.endswith("/allow")
    assert bundle.has_deny_reason()


async def test_allows_and_strips_credential_args(bundle, key):
    f = _filter(bundle, key)
    result = await f.check(_call(key, amount=500, with_auth=False))
    assert result.allowed is True
    # downstream sees only the native arguments — VC bundles stripped
    assert result.arguments == {"amountCents": 500, "merchant": "acme"}
    assert "requestVC" not in result.arguments


async def test_full_chain_allows(bundle, key):
    f = _filter(bundle, key)
    result = await f.check(_call(key, amount=5000, with_auth=True))
    assert result.allowed is True


async def test_tampered_request_denies_with_reason(bundle, key):
    f = _filter(bundle, key)
    call = _call(key, amount=500, with_auth=False)
    jws = call.arguments["requestVC"]["jws"]
    call.arguments["requestVC"]["jws"] = jws[:-6] + ("A" if jws[-1] != "A" else "B") * 6
    result = await f.check(call)
    assert result.allowed is False
    assert "signature is invalid" in result.reason


async def test_over_limit_without_auth_denies(bundle, key):
    f = _filter(bundle, key)
    result = await f.check(_call(key, amount=5000, with_auth=False))
    assert result.allowed is False


async def test_action_mismatch_denies(bundle, key):
    """If the call's tool action doesn't match the signed request's action,
    the policy's requestVC.claims.action == input.tool check fails."""
    f = _filter(bundle, key)
    call = _call(key, amount=500, with_auth=False, tool="payments__transfer")
    result = await f.check(call)
    assert result.allowed is False


async def test_missing_credential_fails_closed(bundle, key):
    f = _filter(bundle, key)
    call = _call(key, amount=500, with_auth=False)
    del call.arguments["requestVC"]
    result = await f.check(call)
    assert result.allowed is False
    assert "could not be assembled" in result.reason


async def test_broken_trust_root_fails_closed(bundle, key):
    f = _filter(bundle, key, config={"trustRootDID": vc.TRUST_DID, "trustRootJwk": "garbage"})
    result = await f.check(_call(key, amount=500, with_auth=False))
    assert result.allowed is False
    assert "failing closed" in result.reason


async def test_arguments_binding_enforced(bundle, key):
    """The signed request's arguments must match the call's native args."""
    f = _filter(bundle, key)
    call = _call(key, amount=500, with_auth=False)
    # tamper the native arg after the request was signed over amount=500
    call.arguments["amountCents"] = 999
    result = await f.check(call)
    assert result.allowed is False

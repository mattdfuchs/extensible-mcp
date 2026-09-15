# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests for the wallet-bundle adapter: decode + cents-normalize + harvest,
producing the ProdSpendInput contract, and the membership lookup
bridge to the did:web resolver."""

from __future__ import annotations

import pytest

from extensible_mcp.didweb import DidWebResolver
from extensible_mcp.types import CallRequest
from extensible_mcp.wallet_bundle import (
    WalletBundleAdapter,
    make_membership_lookup,
)
from tests import vc_helpers as vc

ADMIN_DID = "did:web:admin.example"


@pytest.fixture(scope="module")
def keys():
    return {"kid": vc.new_key(), "parent": vc.new_key(), "admin": vc.new_key()}


def _request_token(keys, *, amount=15.00):
    kid_did = vc.did_key(keys["kid"])
    claims = {
        "iss": kid_did, "nbf": 0, "exp": 9999999999, "jti": "urn:uuid:req1",
        "vc": {"credentialSubject": {
            "id": kid_did,
            "requests": {"type": "spend", "amount": amount, "merchant": "acme"},
        }},
    }
    return vc.sign(claims, keys["kid"])


def _membership_token(keys, who, role):
    return vc.sign(
        {"iss": ADMIN_DID, "sub": vc.did_key(keys[who]), "nbf": 0, "exp": 9999999999,
         "vc": {"credentialSubject": {"role": role}}},
        keys["admin"],
    )


def _auth_token(keys):
    parent_did = vc.did_key(keys["parent"])
    return vc.sign(
        {"iss": parent_did, "nbf": 0, "exp": 9999999999, "jti": "urn:uuid:auth1",
         "vc": {"credentialSubject": {
             "id": parent_did, "authorizes_request": "urn:uuid:req1",
             "request_hash": "sha256:deadbeef"}}},
        keys["parent"],
    )


def _call(keys, *, amount=15.00) -> CallRequest:
    req_bundle = {"token": _request_token(keys, amount=amount),
                  "membership": _membership_token(keys, "kid", "child")}
    auth_bundle = {"token": _auth_token(keys),
                   "membership": _membership_token(keys, "parent", "parent")}
    return CallRequest(
        tool_name="payments__spend",
        arguments={"amount": amount, "merchant": "acme",
                   "requestVC": req_bundle, "authorizationVC": auth_bundle},
        server_name="payments",
    )


def test_envelope_action_and_native_args(keys):
    adapted = WalletBundleAdapter().adapt(_call(keys))
    assert adapted.envelope["tool"] == "spend"  # unqualified action
    args = adapted.envelope["arguments"]
    assert args["amountCents"] == 1500 and "amount" not in args  # seam 1
    assert args["merchant"] == "acme"


def test_wire_names_map_onto_policy_input_fields(keys):
    # A deployment whose wire vocabulary predates the policy's (the VC fork:
    # `vc_request` on the call) still assembles the fetchplan's field names.
    call = _call(keys)
    args = dict(call.arguments)
    args["vc_request"] = args.pop("requestVC")
    args["vc_authorization"] = args.pop("authorizationVC")
    adapter = WalletBundleAdapter(
        request_field="vc_request", authorization_field="vc_authorization"
    )
    adapted = adapter.adapt(
        CallRequest(tool_name=call.tool_name, arguments=args, server_name="payments")
    )
    assert "requestVC" in adapted.envelope and "authorizationVC" in adapted.envelope
    assert "vc_request" not in adapted.envelope
    # native args untouched by the renaming
    assert adapted.envelope["arguments"]["amountCents"] == 1500


def test_request_vc_shape_and_normalized_requests(keys):
    adapted = WalletBundleAdapter().adapt(_call(keys))
    rvc = adapted.envelope["requestVC"]
    assert set(rvc) == {"jws", "claims"}
    requests = rvc["claims"]["vc"]["credentialSubject"]["requests"]
    assert requests["amountCents"] == 1500 and "amount" not in requests  # seam 1 both sides
    assert requests["type"] == "spend"


def test_cents_precision(keys):
    adapted = WalletBundleAdapter().adapt(_call(keys, amount=15.10))
    assert adapted.envelope["arguments"]["amountCents"] == 1510  # not 1509/1511
    requests = adapted.envelope["requestVC"]["claims"]["vc"]["credentialSubject"]["requests"]
    assert requests["amountCents"] == 1510


def test_memberships_harvested_by_subject(keys):
    adapted = WalletBundleAdapter().adapt(_call(keys))
    assert set(adapted.memberships) == {vc.did_key(keys["kid"]), vc.did_key(keys["parent"])}
    kid_m = adapted.memberships[vc.did_key(keys["kid"])]
    assert kid_m["claims"]["vc"]["credentialSubject"]["role"] == "child"


def test_stringified_bundle_is_coerced(keys):
    import json

    call = _call(keys)
    call.arguments["requestVC"] = json.dumps(call.arguments["requestVC"])
    adapted = WalletBundleAdapter().adapt(call)
    assert "requestVC" in adapted.envelope  # parsed despite being a string


def test_missing_bundle_omitted_not_crash(keys):
    call = _call(keys)
    del call.arguments["authorizationVC"]
    adapted = WalletBundleAdapter().adapt(call)
    assert "requestVC" in adapted.envelope
    assert "authorizationVC" not in adapted.envelope


async def test_membership_lookup_bridges_adminkey(keys):
    adapted = WalletBundleAdapter().adapt(_call(keys))
    resolver = DidWebResolver(
        [ADMIN_DID], preresolved={ADMIN_DID: keys["admin"].as_dict(private=False)}
    )
    lookup = make_membership_lookup(adapted.memberships, resolver)

    import json

    kid_membership = await lookup(vc.did_key(keys["kid"]))
    # adminKey is a serialized JWK string
    assert json.loads(kid_membership["adminKey"]) == keys["admin"].as_dict(private=False)
    assert kid_membership["claims"]["sub"] == vc.did_key(keys["kid"])
    # an unknown subject resolves to nothing
    assert await lookup("did:key:zUnknown") is None

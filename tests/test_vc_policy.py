# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""End-to-end production VC enforcement against a real family_spend_prod
bundle: wallet bundles -> adapter -> did:web admin-key -> assemble -> evaluate.

A real multi-key chain (requester did:key, approver did:key, did:web admin),
nested W3C-VC claim shapes, cents normalization, and the conditional
authorization tier — the whole migration target running end to end."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.didweb import DidWebResolver
from extensible_mcp.types import CallRequest
from extensible_mcp.wallet_bundle import WalletBundleAdapter
from extensible_mcp.wasm_filter import VCPolicyFilter
from tests import vc_helpers as vc

PROD_DIR = Path(__file__).parent / "fixtures" / "family_spend_prod"
ADMIN_DID = "did:web:admin.example"


@pytest.fixture(scope="module")
def keys():
    return {"kid": vc.new_key(), "parent": vc.new_key(), "admin": vc.new_key()}


@pytest.fixture
def vc_filter(keys):
    bundle = PolicyBundle.load(PROD_DIR, name="family_spend_prod")
    resolver = DidWebResolver(
        [ADMIN_DID], preresolved={ADMIN_DID: keys["admin"].as_dict(private=False)}
    )
    return VCPolicyFilter(
        bundle,
        adapter=WalletBundleAdapter(),
        resolver=resolver,
        trusted_admin_dids=[ADMIN_DID],
        clock=lambda: 100,
    )


def _membership_token(keys, who, role, *, admin="admin", admin_did=ADMIN_DID):
    return vc.sign(
        {"iss": admin_did, "sub": vc.did_key(keys[who]), "nbf": 0, "exp": 9999999999,
         "vc": {"credentialSubject": {"role": role}}},
        keys[admin],
    )


def _request_bundle(keys, *, amount, merchant="acme", kid_role="child", jti="urn:req1"):
    kid_did = vc.did_key(keys["kid"])
    token = vc.sign(
        {"iss": kid_did, "nbf": 0, "exp": 9999999999, "jti": jti,
         "vc": {"credentialSubject": {
             "id": kid_did, "requests": {"type": "spend", "amount": amount, "merchant": merchant}}}},
        keys["kid"],
    )
    return token, {"token": token, "membership": _membership_token(keys, "kid", kid_role)}


def _auth_bundle(keys, request_token, *, parent_role="parent", req_jti="urn:req1"):
    parent_did = vc.did_key(keys["parent"])
    request_hash = "sha256:" + hashlib.sha256(request_token.encode()).hexdigest()
    token = vc.sign(
        {"iss": parent_did, "nbf": 0, "exp": 9999999999, "jti": "urn:auth1",
         "vc": {"credentialSubject": {
             # `id` is in the contract (the manifest validates it) even
             # though no policy rule reads it — real wallets emit it.
             "id": parent_did,
             "authorizes_request": req_jti, "request_hash": request_hash}}},
        keys["parent"],
    )
    return {"token": token, "membership": _membership_token(keys, "parent", parent_role)}


def _call(keys, *, amount, merchant="acme", with_auth=False, **req_kw) -> CallRequest:
    req_token, req_bundle = _request_bundle(keys, amount=amount, merchant=merchant, **req_kw)
    args = {"amount": amount, "merchant": merchant, "requestVC": req_bundle}
    if with_auth:
        args["authorizationVC"] = _auth_bundle(keys, req_token)
    return CallRequest(tool_name="payments__spend", arguments=args, server_name="payments")


async def test_solo_allows_without_authorization(vc_filter, keys):
    # $5 <= $10 threshold -> solo tier, no authorization needed/omitted
    result = await vc_filter.check(_call(keys, amount=5.00))
    assert result.allowed is True
    # downstream gets the original native args (dollars), credentials stripped
    assert result.arguments == {"amount": 5.00, "merchant": "acme"}


async def test_full_chain_allows(vc_filter, keys):
    result = await vc_filter.check(_call(keys, amount=50.00, with_auth=True))
    assert result.allowed is True


async def test_over_limit_without_auth_denies(vc_filter, keys):
    result = await vc_filter.check(_call(keys, amount=50.00, with_auth=False))
    assert result.allowed is False
    assert "1000" in result.reason  # amountCents <= 1000 violated


async def test_tampered_request_signature_denies(vc_filter, keys):
    call = _call(keys, amount=5.00)
    jws = call.arguments["requestVC"]["token"]
    call.arguments["requestVC"]["token"] = jws[:-6] + ("A" if jws[-1] != "A" else "B") * 6
    result = await vc_filter.check(call)
    assert result.allowed is False
    assert "signature is invalid" in result.reason


async def test_wrong_requester_role_denies(vc_filter, keys):
    result = await vc_filter.check(_call(keys, amount=5.00, kid_role="parent"))
    assert result.allowed is False
    assert "child" in result.reason


async def test_merchant_binding_mismatch_denies(vc_filter, keys):
    # native merchant differs from the signed request's merchant
    call = _call(keys, amount=5.00, merchant="acme")
    call.arguments["merchant"] = "totally-different"
    result = await vc_filter.check(call)
    assert result.allowed is False
    assert "merchant" in result.reason


async def test_amount_binding_mismatch_denies(vc_filter, keys):
    call = _call(keys, amount=5.00)
    call.arguments["amount"] = 9.99  # differs from the signed $5.00
    result = await vc_filter.check(call)
    assert result.allowed is False


async def test_untrusted_admin_denies(vc_filter, keys):
    # a membership signed by an admin not in the trusted set -> no adminKey -> deny
    call = _call(keys, amount=5.00)
    rogue = vc.new_key()
    call.arguments["requestVC"]["membership"] = vc.sign(
        {"iss": "did:web:rogue.example", "sub": vc.did_key(keys["kid"]),
         "nbf": 0, "exp": 9999999999, "vc": {"credentialSubject": {"role": "child"}}},
        rogue,
    )
    result = await vc_filter.check(call)
    assert result.allowed is False
    assert "trusted admin" in result.reason


async def test_full_chain_wrong_binding_denies(vc_filter, keys):
    # authorization that binds to a different request hash
    call = _call(keys, amount=50.00, with_auth=True)
    bad_auth = _auth_bundle(keys, "some-other-token-entirely")
    call.arguments["authorizationVC"] = bad_auth
    result = await vc_filter.check(call)
    assert result.allowed is False
    assert "not bound" in result.reason


async def test_denial_is_disjunctive_with_absent_credential_named(vc_filter, keys):
    # Over-limit without authorization: the solo tier fails at its amount
    # bound (a failed id), the full-chain tier fails by *absence* (no ids —
    # undefined references), so the renderer must name the missing credential
    # and its issuer role from the guidance instead.
    result = await vc_filter.check(_call(keys, amount=50.00, with_auth=False))
    assert result.allowed is False
    r = result.reason
    assert "- Path 1:" in r and "- Path 2:" in r
    assert "1000" in r  # the solo tier's failed amount bound, by sentence
    assert "provide `authorizationVC`, signed by the parent," in r
    assert "retry" in r  # every failed path is re-promptable on this policy


async def test_unbound_extra_argument_fails_closed_via_validation(vc_filter, keys):
    # The policy binds type/amount/merchant individually and ignores an extra
    # native argument — so it allows. The manifest's closed CallArgs is the
    # backstop: validation gates the allow and the call fails closed.
    call = _call(keys, amount=5.00)
    call.arguments["note"] = "smuggled"
    result = await vc_filter.check(call)
    assert result.allowed is False
    assert "failed manifest validation" in result.reason
    assert "note" in result.reason


async def test_validation_opt_out_restores_policy_verdict(keys):
    bundle = PolicyBundle.load(PROD_DIR, name="family_spend_prod")
    resolver = DidWebResolver(
        [ADMIN_DID], preresolved={ADMIN_DID: keys["admin"].as_dict(private=False)}
    )
    unvalidated = VCPolicyFilter(
        bundle,
        adapter=WalletBundleAdapter(),
        resolver=resolver,
        trusted_admin_dids=[ADMIN_DID],
        clock=lambda: 100,
        validate_input=False,
    )
    call = _call(keys, amount=5.00)
    call.arguments["note"] = "smuggled"
    result = await unvalidated.check(call)
    assert result.allowed is True  # the policy alone never reads `note`


async def test_validation_never_masks_a_policy_denial(vc_filter, keys):
    # An untrusted admin yields adminKey=None, which violates the manifest's
    # string type — but the denial the LLM sees must stay the policy's
    # chain-of-trust reason, not a schema error (validation gates allows only).
    call = _call(keys, amount=5.00)
    rogue = vc.new_key()
    call.arguments["requestVC"]["membership"] = vc.sign(
        {"iss": "did:web:rogue.example", "sub": vc.did_key(keys["kid"]),
         "nbf": 0, "exp": 9999999999, "vc": {"credentialSubject": {"role": "child"}}},
        rogue,
    )
    result = await vc_filter.check(call)
    assert result.allowed is False
    assert "trusted admin" in result.reason
    assert "manifest validation" not in result.reason


def test_validate_input_reports_schema_paths():
    bundle = PolicyBundle.load(PROD_DIR, name="family_spend_prod")
    errors = bundle.validate_input({"tool": 42})
    assert errors  # missing required fields, wrong type
    assert any(e.startswith("tool:") for e in errors)


async def test_denial_repeats_shared_failure_per_path(vc_filter, keys):
    # failed_checks is per-path (not deduped like deny_reason): a tampered
    # request signature fails both tiers under distinct ids, so the message
    # carries the sentence on each path.
    call = _call(keys, amount=5.00)
    jws = call.arguments["requestVC"]["token"]
    call.arguments["requestVC"]["token"] = jws[:-6] + ("A" if jws[-1] != "A" else "B") * 6
    result = await vc_filter.check(call)
    assert result.allowed is False
    path1, path2 = (
        next(l for l in result.reason.splitlines() if l.startswith(f"- Path {n}"))
        for n in (1, 2)
    )
    assert "signature is invalid" in path1
    assert "signature is invalid" in path2


async def test_corrupted_token_denies_with_hint_not_traceback(vc_filter, keys):
    # An LLM that retypes a JWS can substitute homoglyphs (observed live:
    # Cyrillic 'Р' for Latin 'P'). Malformed evidence must be a clean denial
    # with a don't-retype hint, never an exception out of the call handler.
    call = _call(keys, amount=5.00)
    header, payload, sig = call.arguments["requestVC"]["token"].split(".")
    mid = len(payload) // 2
    corrupted = payload[:mid] + "Р" + payload[mid + 1:]
    call.arguments["requestVC"]["token"] = f"{header}.{corrupted}.{sig}"
    result = await vc_filter.check(call)
    assert result.allowed is False
    assert "malformed" in result.reason
    assert "do not retype" in result.reason


def test_undefined_reference_comparison_emits_no_failed_check_id():
    # Confirmed live (the pizza run): a bare-comparison
    # check whose reference is undefined (signed request carrying no
    # `merchant`) evaluates to undefined in the wasm runtime — it fires no
    # failed_checks id, unlike the not-form conditions. The renderer's
    # placeholder path ("other conditions...") is the belt for this class.
    bundle = PolicyBundle.load(PROD_DIR, name="family_spend_prod")
    merchant_ids = {
        c["id"]
        for t in bundle.guidance["tiers"]
        for c in t["checks"]
        if "merchant" in (c.get("condition") or "")
    }
    assert merchant_ids  # the binding checks exist in the guidance
    window = {"nbf": 0, "exp": 9999999999}
    assembled = {
        "tool": "spend",
        "arguments": {"amountCents": 500, "merchant": "acme"},
        "requestVC": {
            "jws": "a.b.c",
            "claims": {"jti": "r1", "iss": "did:key:zX", **window,
                       "vc": {"credentialSubject": {
                           # no `merchant` — the undefined reference
                           "requests": {"type": "spend", "amountCents": 500}}}},
        },
        "requesterMembership": {
            "jws": "a.b.c",
            "claims": {"iss": "did:web:x", "sub": "did:key:zX", **window,
                       "vc": {"credentialSubject": {"role": "child"}}},
            "adminKey": None,
        },
        "trustedAdminDids": ["did:web:x"],
        "now": 100,
    }
    allow = bundle.policy.query(assembled, bundle.allow_entrypoint)
    assert not (allow and allow[0].get("result") is True)
    out = bundle.policy.query(assembled, bundle.failed_checks_entrypoint)
    ids = set(out[0]["result"]) if out and "result" in out[0] else set()
    assert ids  # the not-form checks (signatures, chain) do fire
    assert not (ids & merchant_ids)  # the undefined comparison stays silent

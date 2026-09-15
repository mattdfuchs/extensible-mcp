# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""End-to-end WebAuthn approval enforcement against a real
family_spend_webauthn bundle — the companion rail to test_vc_policy.py's
wallet-approved chain. Request side is the same did:key + did:web pattern;
the authorization side is a passkey assertion checked by the
``verify_webauthn`` host builtin, with the challenge→action binding
enforced in-policy."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.types import CallRequest
from extensible_mcp.wasm_filter import WasmPolicyFilter
from extensible_mcp.wasm_policy import PolicyEvaluationError, default_builtins
from tests import vc_helpers as vc

WA_DIR = Path(__file__).parent / "fixtures" / "family_spend_webauthn"
ADMIN_DID = "did:web:admin.example"
RP_ID = "approval.example"
ORIGIN = "https://approval.example"
CRED_ID = "cred-1"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def keys():
    return {"kid": vc.new_key(), "admin": vc.new_key()}


@pytest.fixture(scope="module")
def passkey():
    return ec.generate_private_key(ec.SECP256R1())


def _passkey_jwk(passkey) -> str:
    nums = passkey.public_key().public_numbers()
    return json.dumps(
        {"kty": "EC", "crv": "P-256",
         "x": _b64u(nums.x.to_bytes(32, "big")),
         "y": _b64u(nums.y.to_bytes(32, "big"))}
    )


def _approval(passkey, *, amount_cents, merchant="acme", tool="spend"):
    """A synthetic passkey assertion over the canonical action."""
    canonical = f"legov1|spend|{tool}|{amount_cents}|{merchant}".encode()
    challenge = hashlib.sha256(canonical).hexdigest().encode()
    cd = json.dumps(
        {"type": "webauthn.get", "challenge": _b64u(challenge), "origin": ORIGIN}
    ).encode()
    ad = hashlib.sha256(RP_ID.encode()).digest() + bytes([0x05]) + (0).to_bytes(4, "big")
    sig = passkey.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
    return {"credentialId": CRED_ID, "authenticatorData": _b64u(ad),
            "clientDataJSON": _b64u(cd), "signature": _b64u(sig)}


def _request_vc(keys, *, amount_cents, merchant="acme"):
    kid_did = vc.did_key(keys["kid"])
    claims = {
        "iss": kid_did, "nbf": 0, "exp": 9999999999, "jti": "urn:req1",
        "vc": {"credentialSubject": {
            "id": kid_did,
            "requests": {"type": "spend", "amountCents": amount_cents, "merchant": merchant}}},
    }
    return {"jws": vc.sign(claims, keys["kid"]), "claims": claims}


def _envelope(keys, *, sub, subject_claims):
    claims = {"iss": ADMIN_DID, "sub": sub, "nbf": 0, "exp": 9999999999,
              "vc": {"credentialSubject": subject_claims}}
    return {"jws": vc.sign(claims, keys["admin"]), "claims": claims,
            "adminKey": vc.public_jwk(keys["admin"])}


def _filter(keys, passkey, *, enrollment_role="parent"):
    bundle = PolicyBundle.load(
        WA_DIR, name="family_spend_webauthn",
        builtins=default_builtins(webauthn_rp_id=RP_ID),
    )
    wallets = {
        vc.did_key(keys["kid"]): _envelope(
            keys, sub=vc.did_key(keys["kid"]), subject_claims={"role": "child"}
        ),
        CRED_ID: _envelope(
            keys, sub=CRED_ID,
            subject_claims={"role": enrollment_role, "publicKey": _passkey_jwk(passkey)},
        ),
    }

    async def lookup(subject):
        return wallets.get(subject)

    return WasmPolicyFilter(
        bundle,
        config={"webauthnOrigin": ORIGIN, "trustedAdminDids": [ADMIN_DID]},
        wallet_lookup=lookup,
        clock=lambda: 100,
    )


def _call(keys, *, amount_cents, merchant="acme", approval=None) -> CallRequest:
    args = {"amountCents": amount_cents, "merchant": merchant,
            "requestVC": _request_vc(keys, amount_cents=amount_cents, merchant=merchant)}
    if approval is not None:
        args["approval"] = approval
    return CallRequest(tool_name="payments__spend", arguments=args, server_name="payments")


def test_load_without_rp_id_fails_closed():
    # The wasm imports verify_webauthn; without a configured relying party the
    # bundle must refuse to load, not evaluate with a missing builtin.
    with pytest.raises(PolicyEvaluationError, match="verify_webauthn"):
        PolicyBundle.load(WA_DIR, name="family_spend_webauthn")


async def test_solo_allows_without_approval(keys, passkey):
    result = await _filter(keys, passkey).check(_call(keys, amount_cents=500))
    assert result.allowed is True
    assert result.arguments == {"amountCents": 500, "merchant": "acme"}


async def test_webauthn_full_chain_allows(keys, passkey):
    approval = _approval(passkey, amount_cents=5000)
    result = await _filter(keys, passkey).check(
        _call(keys, amount_cents=5000, approval=approval)
    )
    assert result.allowed is True


async def test_signature_for_one_action_cannot_authorize_another(keys, passkey):
    # The headline property: a valid assertion whose challenge binds a
    # different action (other merchant) must not authorize this call.
    approval = _approval(passkey, amount_cents=5000, merchant="other-shop")
    result = await _filter(keys, passkey).check(
        _call(keys, amount_cents=5000, approval=approval)
    )
    assert result.allowed is False
    assert "not bound to this exact call" in result.reason


async def test_tampered_assertion_denies(keys, passkey):
    approval = _approval(passkey, amount_cents=5000)
    sig = approval["signature"]
    approval["signature"] = sig[:-6] + ("A" if sig[-1] != "A" else "B") * 6
    result = await _filter(keys, passkey).check(
        _call(keys, amount_cents=5000, approval=approval)
    )
    assert result.allowed is False
    assert "passkey assertion is invalid" in result.reason


async def test_enrollment_role_enforced(keys, passkey):
    # A passkey enrolled by the admin but with the wrong role cannot approve.
    approval = _approval(passkey, amount_cents=5000)
    result = await _filter(keys, passkey, enrollment_role="child").check(
        _call(keys, amount_cents=5000, approval=approval)
    )
    assert result.allowed is False
    assert "parent" in result.reason


async def test_over_limit_without_approval_names_the_missing_field(keys, passkey):
    result = await _filter(keys, passkey).check(_call(keys, amount_cents=5000))
    assert result.allowed is False
    assert "provide `approval`" in result.reason


# --------------------------------------------------------------------------- #
# VCPolicyFilter wiring (the production shape: wallet bundles + enrollment
# fallback + webauthnOrigin via extra_config)
# --------------------------------------------------------------------------- #

from extensible_mcp.didweb import DidWebResolver  # noqa: E402
from extensible_mcp.wallet_bundle import WalletBundleAdapter  # noqa: E402
from extensible_mcp.wasm_filter import VCPolicyFilter  # noqa: E402


class _ApprovalLiftAdapter(WalletBundleAdapter):
    """The wire adapter a WebAuthn deployment runs: the request rides as a
    wallet bundle, the passkey assertion rides as ``approval`` and must land
    at the input's top level (naming it the authorization field makes the
    filter strip it from the downstream call)."""

    def __init__(self) -> None:
        super().__init__(authorization_field="approval")

    def adapt(self, request: CallRequest):
        args = dict(request.arguments)
        approval = args.pop("approval", None)
        adapted = super().adapt(
            CallRequest(
                tool_name=request.tool_name,
                arguments=args,
                server_name=request.server_name,
            )
        )
        if isinstance(approval, dict):
            adapted.envelope["approval"] = approval
        return adapted


def _wa_vc_filter(keys, passkey, *, with_origin=True):
    bundle = PolicyBundle.load(
        WA_DIR, name="family_spend_webauthn",
        builtins=default_builtins(webauthn_rp_id=RP_ID),
    )
    resolver = DidWebResolver(
        [ADMIN_DID], preresolved={ADMIN_DID: keys["admin"].as_dict(private=False)}
    )
    enrollment = _envelope(
        keys, sub=CRED_ID,
        subject_claims={"role": "parent", "publicKey": _passkey_jwk(passkey)},
    )

    async def enrollment_fallback(subject):
        return enrollment if subject == CRED_ID else None

    return VCPolicyFilter(
        bundle,
        adapter=_ApprovalLiftAdapter(),
        resolver=resolver,
        trusted_admin_dids=[ADMIN_DID],
        clock=lambda: 100,
        extra_config={"webauthnOrigin": ORIGIN} if with_origin else None,
        wallet_fallback=enrollment_fallback,
    )


def _wa_bundle_call(keys, *, amount_cents, approval=None) -> CallRequest:
    kid_did = vc.did_key(keys["kid"])
    claims = {
        "iss": kid_did, "nbf": 0, "exp": 9999999999, "jti": "urn:req1",
        "vc": {"credentialSubject": {
            "id": kid_did,
            "requests": {"type": "spend", "amountCents": amount_cents, "merchant": "acme"}}},
    }
    membership_token = vc.sign(
        {"iss": ADMIN_DID, "sub": kid_did, "nbf": 0, "exp": 9999999999,
         "vc": {"credentialSubject": {"role": "child"}}},
        keys["admin"],
    )
    args = {
        "amountCents": amount_cents, "merchant": "acme",
        "requestVC": {"token": vc.sign(claims, keys["kid"]), "membership": membership_token},
    }
    if approval is not None:
        args["approval"] = approval
    return CallRequest(tool_name="payments__spend", arguments=args, server_name="payments")


async def test_vc_filter_full_webauthn_chain_allows(keys, passkey):
    wa_filter = _wa_vc_filter(keys, passkey)
    result = await wa_filter.check(
        _wa_bundle_call(keys, amount_cents=5000,
                        approval=_approval(passkey, amount_cents=5000))
    )
    assert result.allowed is True
    # request bundle and assertion both stripped from the downstream call
    assert result.arguments == {"amountCents": 5000, "merchant": "acme"}


async def test_vc_filter_solo_webauthn_allows_without_approval(keys, passkey):
    wa_filter = _wa_vc_filter(keys, passkey)
    result = await wa_filter.check(_wa_bundle_call(keys, amount_cents=500))
    assert result.allowed is True


async def test_vc_filter_missing_origin_config_fails_closed(keys, passkey):
    wa_filter = _wa_vc_filter(keys, passkey, with_origin=False)
    result = await wa_filter.check(_wa_bundle_call(keys, amount_cents=500))
    assert result.allowed is False
    assert "webauthnOrigin" in result.reason

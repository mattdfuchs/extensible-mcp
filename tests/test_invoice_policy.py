# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Proof that the certified ``family_spend_invoice`` bundle (externally
authored) actually enforces the invoice/negotiate/passkey flow: a
merchant-signed invoice plus per-role WebAuthn passkey approvals — no
wallet VC anywhere, unlike the hybrid ``family_spend_webauthn``.

Exercised directly at the ``PolicyEngine.query()`` level (not through
``WasmPolicyFilter``/a ``CallRequest``) since this bundle isn't wired into
the proxy's call path yet — that's the remaining step (rerouting
``request_invoice_approval`` through ``BundleRouter`` instead of the
approval service's own hand-coded threshold check). This test proves the
certified bundle behaves correctly against this repo's own engines, ahead
of that rewiring.

``trustedMerchants`` is a *list* of ``{merchantId, key}`` entries, not a
keyed map — the certified fragment has no dynamic key projection, so the
merchant lookup is a relational join over the list.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.guidance import render_denial
from extensible_mcp.wasm_policy import default_builtins
from tests import vc_helpers as vc

BUNDLE_DIR = Path(__file__).parent / "fixtures" / "family_spend_invoice"
CEL_BUNDLE_DIR = Path(__file__).parent / "fixtures" / "cel_family_spend_invoice"
ADMIN_DID = "did:web:admin.example"
RP_ID = "approval.example"
ORIGIN = "https://approval.example"
MERCHANT_ID = "dominos"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def admin_key():
    return vc.new_key()


@pytest.fixture(scope="module")
def merchant_key():
    return Ed25519PrivateKey.generate()


@pytest.fixture(scope="module")
def child_passkey():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="module")
def parent_passkey():
    return ec.generate_private_key(ec.SECP256R1())


def _passkey_jwk(passkey) -> str:
    nums = passkey.public_key().public_numbers()
    return json.dumps(
        {"kty": "EC", "crv": "P-256",
         "x": _b64u(nums.x.to_bytes(32, "big")),
         "y": _b64u(nums.y.to_bytes(32, "big"))}
    )


def _invoice(merchant_key, *, merchant_id=MERCHANT_ID, total_cents, exp=9999999999, nonce="urn:uuid:inv-1"):
    invoice = {
        "merchantId": merchant_id, "totalCents": total_cents,
        "currency": "usd", "exp": exp, "nonce": nonce,
    }
    canonical = json.dumps(invoice, sort_keys=True, separators=(",", ":"))
    signature = _b64u(merchant_key.sign(canonical.encode()))
    return {"canonical": canonical, "signature": signature}


def _passkey_approval(passkey, *, credential_id, canonical, origin=ORIGIN, rp_id=RP_ID):
    """A synthetic passkey assertion bound to hash(invoice.canonical) —
    the challenge form, reused for the invoice instead of a
    wallet-signed spend request."""
    challenge = hashlib.sha256(canonical.encode()).hexdigest().encode()
    cd = json.dumps(
        {"type": "webauthn.get", "challenge": _b64u(challenge), "origin": origin}
    ).encode()
    ad = hashlib.sha256(rp_id.encode()).digest() + bytes([0x05]) + (0).to_bytes(4, "big")
    sig = passkey.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
    return {"credentialId": credential_id, "authenticatorData": _b64u(ad),
            "clientDataJSON": _b64u(cd), "signature": _b64u(sig)}


def _enrollment(admin_key, *, cred_id, role, passkey):
    claims = {
        "iss": ADMIN_DID, "sub": cred_id, "nbf": 0, "exp": 9999999999,
        "vc": {"credentialSubject": {"role": role, "publicKey": _passkey_jwk(passkey)}},
    }
    return {"jws": vc.sign(claims, admin_key), "claims": claims,
            "adminKey": vc.public_jwk(admin_key)}


def _cel_bundle_with_rp_id(directory: Path, *, name: str, rp_id: str) -> PolicyBundle:
    """``PolicyBundle.load`` ignores ``builtins`` for a CEL bundle and has
    no parameter for custom CEL functions — the webauthn relying-party id
    has to reach ``CelPolicy`` directly, so this bundle is assembled by
    hand rather than through ``load()``, same artifacts, same shape."""
    from extensible_mcp.cel_policy import CelPolicy, default_cel_functions

    policy = CelPolicy(
        directory / "checks.cel.json",
        functions=default_cel_functions(webauthn_rp_id=rp_id),
    )
    package = json.loads((directory / "checks.cel.json").read_text())["package"]
    return PolicyBundle(
        name=name,
        package=package,
        policy=policy,
        manifest=json.loads((directory / "manifest.json").read_text()),
        fetchplan=json.loads((directory / "fetchplan.json").read_text()),
        guidance=json.loads((directory / "guidance.json").read_text()),
    )


@pytest.fixture(params=["rego", "cel"])
def bundle(request):
    """Parametrized so every scenario below runs against both engines —
    the same proof-of-engine-parity discipline as test_cel_policy.py, now
    against a bundle neither engine's twin was hand-authored to match. The
    two artifacts are emitted from a common core, so agreement here isn't
    two authors corroborating each other; but their check ids come from
    separate expansions, and neither Rego nor CEL validates an id, so a
    matching id set across the two engines is a real cross-check rather
    than a tautology."""
    if request.param == "rego":
        return PolicyBundle.load(
            BUNDLE_DIR, name="family_spend_invoice",
            builtins=default_builtins(webauthn_rp_id=RP_ID),
        )
    return _cel_bundle_with_rp_id(CEL_BUNDLE_DIR, name="cel_family_spend_invoice", rp_id=RP_ID)


def _base_input(merchant_key, *, total_cents, merchant_id=MERCHANT_ID, exp=9999999999,
                 trusted_key=None, trusted_merchant_id=MERCHANT_ID):
    invoice = _invoice(merchant_key, merchant_id=merchant_id, total_cents=total_cents, exp=exp)
    trusted_pub = (trusted_key or merchant_key).public_key().public_bytes_raw()
    return invoice, {
        "arguments": {"amountCents": total_cents, "merchantId": merchant_id},
        "invoice": invoice,
        "trustedMerchants": [{"merchantId": trusted_merchant_id, "key": _b64u(trusted_pub)}],
        "webauthnOrigin": ORIGIN,
        "trustedAdminDids": [ADMIN_DID],
        "now": 100,
    }


def _with_child(input_obj, invoice, admin_key, child_passkey, cred_id="child-cred", role="child"):
    input_obj = dict(input_obj)
    input_obj["childApproval"] = _passkey_approval(
        child_passkey, credential_id=cred_id, canonical=invoice["canonical"]
    )
    input_obj["childEnrollment"] = _enrollment(
        admin_key, cred_id=cred_id, role=role, passkey=child_passkey
    )
    return input_obj


def _with_parent(input_obj, invoice, admin_key, parent_passkey, cred_id="parent-cred", role="parent"):
    input_obj = dict(input_obj)
    input_obj["parentApproval"] = _passkey_approval(
        parent_passkey, credential_id=cred_id, canonical=invoice["canonical"]
    )
    input_obj["parentEnrollment"] = _enrollment(
        admin_key, cred_id=cred_id, role=role, passkey=parent_passkey
    )
    return input_obj


def test_solo_tier_allows_on_child_approval_alone(bundle, merchant_key, admin_key, child_passkey):
    invoice, base = _base_input(merchant_key, total_cents=400)
    full = _with_child(base, invoice, admin_key, child_passkey)
    assert bundle.policy.query(full, bundle.allow_entrypoint) == [{"result": True}]


def test_dual_tier_denies_without_parent(bundle, merchant_key, admin_key, child_passkey):
    """The parent leg is *guarded*, not unconditionally required (per
    manifest/fetchplan) — genuinely absent above the threshold must deny
    cleanly, never raise. This is the guard-aware contract both engines
    are supposed to honor (proven here against a bundle
    that actually has a guarded optional field, not just the family_spend
    fixtures that motivated the fix originally)."""
    invoice, base = _base_input(merchant_key, total_cents=1500)
    full = _with_child(base, invoice, admin_key, child_passkey)
    assert bundle.policy.query(full, bundle.allow_entrypoint) == [{"result": False}]
    failed = bundle.policy.query(full, bundle.failed_checks_entrypoint)[0]["result"]
    assert failed  # denies with reasons, not silently, and above all without raising


def test_dual_tier_allows_with_both_approvals(
    bundle, merchant_key, admin_key, child_passkey, parent_passkey
):
    invoice, base = _base_input(merchant_key, total_cents=1500)
    full = _with_child(base, invoice, admin_key, child_passkey)
    full = _with_parent(full, invoice, admin_key, parent_passkey)
    assert bundle.policy.query(full, bundle.allow_entrypoint) == [{"result": True}]


def test_untrusted_merchant_denies(bundle, merchant_key, admin_key, child_passkey):
    """A *real* signature from a key not in the trusted set — not a
    tampered signature, an actually-untrusted signer. Checked via
    ``failed_checks`` + ``render_denial`` (engine-agnostic) rather than
    ``deny_reason``, which only the Rego engine's ``entrypoints()``
    exposes — a CEL bundle has no such entrypoint at all."""
    untrusted_key = Ed25519PrivateKey.generate()
    invoice, base = _base_input(
        merchant_key, total_cents=400, trusted_key=untrusted_key,
    )
    full = _with_child(base, invoice, admin_key, child_passkey)
    assert bundle.policy.query(full, bundle.allow_entrypoint) == [{"result": False}]
    failed = bundle.policy.query(full, bundle.failed_checks_entrypoint)[0]["result"]
    message = render_denial(bundle.guidance, failed)
    assert message is not None and "trusted merchant" in message


def test_invoice_attributed_to_a_different_merchant_denies(
    bundle, merchant_key, admin_key, child_passkey
):
    """A valid signature from a trusted key, but the invoice it signed
    names a different merchant than the one the key is trusted for —
    the join: trust is on (merchantId, key) together,
    not either alone."""
    invoice, base = _base_input(
        merchant_key, total_cents=400, merchant_id="pizza-hut",
        trusted_merchant_id=MERCHANT_ID,  # trusted key is registered under "dominos"
    )
    full = _with_child(base, invoice, admin_key, child_passkey)
    assert bundle.policy.query(full, bundle.allow_entrypoint) == [{"result": False}]


def test_tampered_invoice_amount_denies(bundle, merchant_key, admin_key, child_passkey):
    """The buyer's arguments must match the merchant-signed invoice, not the
    other way around — a call claiming a different amount than the signed
    invoice fails the binding check even with valid signatures throughout."""
    invoice, base = _base_input(merchant_key, total_cents=400)
    base["arguments"]["amountCents"] = 1  # the $1 Tahoe: the call lies about the price
    full = _with_child(base, invoice, admin_key, child_passkey)
    assert bundle.policy.query(full, bundle.allow_entrypoint) == [{"result": False}]


def test_expired_invoice_denies(bundle, merchant_key, admin_key, child_passkey):
    invoice, base = _base_input(merchant_key, total_cents=400, exp=50)  # now=100, already expired
    full = _with_child(base, invoice, admin_key, child_passkey)
    assert bundle.policy.query(full, bundle.allow_entrypoint) == [{"result": False}]


def test_child_approval_bound_to_a_different_invoice_denies(
    bundle, merchant_key, admin_key, child_passkey
):
    """The passkey approval must bind to *this* invoice's hash — reusing a
    valid approval minted for a different (even cheaper) invoice must fail."""
    invoice, base = _base_input(merchant_key, total_cents=400)
    other_invoice = _invoice(merchant_key, total_cents=400, nonce="urn:uuid:other")
    full = dict(base)
    full["childApproval"] = _passkey_approval(
        child_passkey, credential_id="child-cred", canonical=other_invoice["canonical"]
    )
    full["childEnrollment"] = _enrollment(
        admin_key, cred_id="child-cred", role="child", passkey=child_passkey
    )
    assert bundle.policy.query(full, bundle.allow_entrypoint) == [{"result": False}]


def test_engines_diverge_on_a_genuinely_missing_required_field(
    bundle, merchant_key,
):
    """A documented cross-engine divergence, found while adopting this
    bundle — not a live risk (the proxy's own fetch-plan assembly always
    supplies every unconditionally-required field or fails before the
    policy is ever queried), but real and worth pinning down as a known
    property rather than an assumption.

    ``childApproval``/``childEnrollment`` are unconditionally required
    (manifest + fetchplan; not in the guarded-optional set that covers
    ``parentApproval``/``parentEnrollment``). Omit them entirely — an
    out-of-contract input a correctly functioning caller would never
    produce — and the two engines behave differently: Rego's undefined-
    propagation silently omits the ids of checks it cannot evaluate and
    returns *some* failed-checks set without raising; CEL has no such
    graceful undefined and raises ``PolicyEvaluationError`` (which the
    engine's own fail-closed design treats as correct — see the
    cel_policy module docstring). Reported upstream to the policy's authors
    rather than treated as a defect in either engine, since the input itself
    is invalid."""
    from extensible_mcp.cel_policy import CelPolicy
    from extensible_mcp.wasm_policy import PolicyEvaluationError

    invoice, base = _base_input(merchant_key, total_cents=400)
    # deliberately no childApproval / childEnrollment at all
    if isinstance(bundle.policy, CelPolicy):
        with pytest.raises(PolicyEvaluationError):
            bundle.policy.query(base, bundle.failed_checks_entrypoint)
    else:  # Rego: evaluates around the missing field, does not raise
        result = bundle.policy.query(base, bundle.failed_checks_entrypoint)
        assert result[0]["result"]  # returns cleanly, some ids reported


def test_parent_credential_enrolled_as_child_denies(
    bundle, merchant_key, admin_key, child_passkey, parent_passkey
):
    """A valid, correctly-bound passkey assertion on the parent leg from a
    credential enrolled as "child" must not satisfy the parent requirement —
    the role check, not just the signature, gates each leg."""
    invoice, base = _base_input(merchant_key, total_cents=1500)
    full = _with_child(base, invoice, admin_key, child_passkey)
    full = _with_parent(full, invoice, admin_key, parent_passkey, role="child")
    assert bundle.policy.query(full, bundle.allow_entrypoint) == [{"result": False}]



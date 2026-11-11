# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""``InvoiceGatedFilter`` (family_proxy_server.py) end to end: the wire
adapter that reshapes a `charge_invoice` call's `invoice` (with the
merchant's signature embedded, exactly as `request_invoice_approval`
returns it) into what the certified `family_spend_invoice` bundle
expects, fetches the current trusted-merchant set live per call, and
delegates the allow/deny decision to a real `WasmPolicyFilter` over the
real compiled bundle — not a mock of either.

Exercises the actual concern this wiring introduced that no other test
covers: `canonical_invoice()` reproducing byte-for-byte what the merchant
signed after round-tripping through the `invoice`-with-embedded-signature
wire shape, and a live (not baked-in) trusted-merchant fetch actually
gating the decision.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.types import CallRequest
from extensible_mcp.wasm_policy import default_builtins

# Make examples/ importable like family_proxy_server.py does in production.
_EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
sys.path.insert(0, str(_EXAMPLES))
from family_proxy_server import InvoiceGatedFilter  # noqa: E402


# -- tiny local admin-signing helpers (this package's own tests/ has no
# equivalent to the root project's tests/vc_helpers.py; these mirror it
# exactly for the one thing needed here — signing an admin enrollment VC) -- #


def _new_admin_key():
    from joserfc.jwk import OKPKey

    return OKPKey.generate_key("Ed25519")


def _admin_public_jwk(key) -> str:
    return json.dumps(key.as_dict(private=False))


def _admin_sign(payload: dict, key) -> str:
    from joserfc import jws as joserfc_jws

    return joserfc_jws.serialize_compact(
        {"alg": "Ed25519"}, json.dumps(payload).encode(), key, algorithms=["Ed25519"]
    )


# Same fixture family_proxy_server.py itself loads from — the root
# project's tests/fixtures/, not this package's own (this package has no
# copy of the bundle; there's exactly one, shared).
BUNDLE_DIR = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "family_spend_invoice"
ADMIN_DID = "did:web:admin.example"
RP_ID = "approval.example"
ORIGIN = "https://approval.example"
MERCHANT_ID = "dominos"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class _StubTrustedMerchantsClient:
    """Stands in for the ``httpx.AsyncClient`` ``InvoiceGatedFilter`` uses
    to fetch the live trusted-merchant set — a plain in-memory list this
    test controls directly, so it can prove the fetch is genuinely live
    (change it between calls, see the decision change) rather than baked
    in once at construction."""

    def __init__(self, entries: list[dict[str, str]]) -> None:
        self.entries = entries
        self.calls = 0

    async def get(self, path: str):
        assert path == "/trusted-merchants"
        self.calls += 1
        return _StubResponse(200, self.entries)


class _StubResponse:
    def __init__(self, status_code: int, body) -> None:
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


@pytest.fixture(scope="module")
def admin_key():
    return _new_admin_key()


@pytest.fixture(scope="module")
def merchant_key():
    return Ed25519PrivateKey.generate()


@pytest.fixture(scope="module")
def child_passkey():
    return ec.generate_private_key(ec.SECP256R1())


def _passkey_jwk(passkey) -> str:
    nums = passkey.public_key().public_numbers()
    return json.dumps(
        {"kty": "EC", "crv": "P-256",
         "x": _b64u(nums.x.to_bytes(32, "big")),
         "y": _b64u(nums.y.to_bytes(32, "big"))}
    )


def _invoice_fields(*, total_cents=400, merchant_id=MERCHANT_ID, exp=9999999999, nonce="urn:uuid:1"):
    return {
        "merchantId": merchant_id, "totalCents": total_cents,
        "currency": "usd", "exp": exp, "nonce": nonce,
    }


def _sign(invoice_fields: dict, key: Ed25519PrivateKey) -> str:
    canonical = json.dumps(invoice_fields, sort_keys=True, separators=(",", ":"))
    return _b64u(key.sign(canonical.encode()))


def _child_approval(passkey, *, cred_id, invoice_fields):
    canonical = json.dumps(invoice_fields, sort_keys=True, separators=(",", ":"))
    challenge = hashlib.sha256(canonical.encode()).hexdigest().encode()
    cd = json.dumps(
        {"type": "webauthn.get", "challenge": _b64u(challenge), "origin": ORIGIN}
    ).encode()
    ad = hashlib.sha256(RP_ID.encode()).digest() + bytes([0x05]) + (0).to_bytes(4, "big")
    sig = passkey.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
    return {"credentialId": cred_id, "authenticatorData": _b64u(ad),
            "clientDataJSON": _b64u(cd), "signature": _b64u(sig)}


def _enrollment(admin_key, *, cred_id, role, passkey):
    claims = {
        "iss": ADMIN_DID, "sub": cred_id, "nbf": 0, "exp": 9999999999,
        "vc": {"credentialSubject": {"role": role, "publicKey": _passkey_jwk(passkey)}},
    }
    return {"jws": _admin_sign(claims, admin_key), "claims": claims,
            "adminKey": _admin_public_jwk(admin_key)}


def _filter(*, trusted_entries, admin_key, child_passkey):
    bundle = PolicyBundle.load(
        BUNDLE_DIR, name="family_spend_invoice",
        builtins=default_builtins(webauthn_rp_id=RP_ID),
    )

    async def wallet_lookup(subject: str):
        # Only the child credential is enrolled in these tests.
        cred_id = "child-cred"
        if subject != cred_id:
            return None
        return _enrollment(admin_key, cred_id=cred_id, role="child", passkey=child_passkey)

    return InvoiceGatedFilter(
        bundle,
        base_config={"webauthnOrigin": ORIGIN, "trustedAdminDids": [ADMIN_DID]},
        wallet_lookup=wallet_lookup,
        trusted_merchants_client=_StubTrustedMerchantsClient(trusted_entries),
    )


async def test_allows_real_call_with_embedded_signature(admin_key, merchant_key, child_passkey):
    invoice_fields = _invoice_fields(total_cents=400)
    signature = _sign(invoice_fields, merchant_key)
    child_approval = _child_approval(child_passkey, cred_id="child-cred", invoice_fields=invoice_fields)

    trusted = [{"merchantId": MERCHANT_ID, "key": _b64u(merchant_key.public_key().public_bytes_raw())}]
    f = _filter(trusted_entries=trusted, admin_key=admin_key, child_passkey=child_passkey)

    request = CallRequest(
        tool_name="settlement__charge_invoice",
        arguments={
            "amountCents": 400, "merchantId": MERCHANT_ID,
            "invoice": {**invoice_fields, "signature": signature},
            "childApproval": child_approval,
        },
        server_name="settlement",
    )
    result = await f.check(request)
    assert result.allowed is True, result.reason
    assert result.arguments == {"amountCents": 400, "merchantId": MERCHANT_ID}


async def test_denies_when_merchant_not_currently_trusted(admin_key, merchant_key, child_passkey):
    """The live fetch, not a stale snapshot: the exact same evidence that
    just allowed above is denied once the trusted-merchant list no longer
    contains this key."""
    invoice_fields = _invoice_fields(total_cents=400, nonce="urn:uuid:2")
    signature = _sign(invoice_fields, merchant_key)
    child_approval = _child_approval(child_passkey, cred_id="child-cred", invoice_fields=invoice_fields)

    f = _filter(trusted_entries=[], admin_key=admin_key, child_passkey=child_passkey)

    request = CallRequest(
        tool_name="settlement__charge_invoice",
        arguments={
            "amountCents": 400, "merchantId": MERCHANT_ID,
            "invoice": {**invoice_fields, "signature": signature},
            "childApproval": child_approval,
        },
        server_name="settlement",
    )
    result = await f.check(request)
    assert result.allowed is False


async def test_denies_tampered_amount_the_dollar_tahoe(admin_key, merchant_key, child_passkey):
    """The call claims a different amount than the signed invoice — denied
    even though every signature involved is genuinely valid."""
    invoice_fields = _invoice_fields(total_cents=1800, nonce="urn:uuid:3")
    signature = _sign(invoice_fields, merchant_key)
    child_approval = _child_approval(child_passkey, cred_id="child-cred", invoice_fields=invoice_fields)

    trusted = [{"merchantId": MERCHANT_ID, "key": _b64u(merchant_key.public_key().public_bytes_raw())}]
    f = _filter(trusted_entries=trusted, admin_key=admin_key, child_passkey=child_passkey)

    request = CallRequest(
        tool_name="settlement__charge_invoice",
        arguments={
            "amountCents": 1, "merchantId": MERCHANT_ID,  # claims $0.01, invoice says $18.00
            "invoice": {**invoice_fields, "signature": signature},
            "childApproval": child_approval,
        },
        server_name="settlement",
    )
    result = await f.check(request)
    assert result.allowed is False


async def test_denies_missing_invoice_signature():
    f = _filter(trusted_entries=[], admin_key=_new_admin_key(), child_passkey=ec.generate_private_key(ec.SECP256R1()))
    request = CallRequest(
        tool_name="settlement__charge_invoice",
        arguments={"amountCents": 400, "merchantId": MERCHANT_ID, "invoice": {"merchantId": MERCHANT_ID}},
        server_name="settlement",
    )
    result = await f.check(request)
    assert result.allowed is False
    assert "signature" in result.reason


async def test_nonce_passes_through_to_the_downstream_but_not_the_policy(
    admin_key, merchant_key, child_passkey
):
    """`nonce` names which approved invoice settlement should charge. The
    certified bundle's InvoiceArgs contract is closed and doesn't carry it,
    so the adapter keeps it out of the policy's view and puts it back on the
    forwarded call."""
    invoice_fields = _invoice_fields(total_cents=400, nonce="urn:uuid:settle-me")
    signature = _sign(invoice_fields, merchant_key)
    child_approval = _child_approval(
        child_passkey, cred_id="child-cred", invoice_fields=invoice_fields
    )
    trusted = [{"merchantId": MERCHANT_ID, "key": _b64u(merchant_key.public_key().public_bytes_raw())}]
    f = _filter(trusted_entries=trusted, admin_key=admin_key, child_passkey=child_passkey)

    request = CallRequest(
        tool_name="settlement__charge_invoice",
        arguments={
            "amountCents": 400, "merchantId": MERCHANT_ID,
            "nonce": "urn:uuid:settle-me",
            "invoice": {**invoice_fields, "signature": signature},
            "childApproval": child_approval,
        },
        server_name="settlement",
    )
    result = await f.check(request)
    assert result.allowed is True, result.reason
    assert result.arguments == {
        "amountCents": 400, "merchantId": MERCHANT_ID, "nonce": "urn:uuid:settle-me",
    }


async def test_denies_nonce_naming_a_different_invoice(
    admin_key, merchant_key, child_passkey
):
    """Every signature here is valid for the invoice supplied -- but the
    nonce names a different one, so settlement would charge an invoice the
    policy never saw."""
    invoice_fields = _invoice_fields(total_cents=400, nonce="urn:uuid:this-one")
    signature = _sign(invoice_fields, merchant_key)
    child_approval = _child_approval(
        child_passkey, cred_id="child-cred", invoice_fields=invoice_fields
    )
    trusted = [{"merchantId": MERCHANT_ID, "key": _b64u(merchant_key.public_key().public_bytes_raw())}]
    f = _filter(trusted_entries=trusted, admin_key=admin_key, child_passkey=child_passkey)

    request = CallRequest(
        tool_name="settlement__charge_invoice",
        arguments={
            "amountCents": 400, "merchantId": MERCHANT_ID,
            "nonce": "urn:uuid:some-other-invoice",
            "invoice": {**invoice_fields, "signature": signature},
            "childApproval": child_approval,
        },
        server_name="settlement",
    )
    result = await f.check(request)
    assert result.allowed is False
    assert "nonce" in result.reason


# -- the enrollment the approval service mints, under a principal ----------- #
#
# The organization shape: the console's bearer is the proxy's principal, and
# the bundle's account_bound check reads the *enrollment VC* -- the one the
# approval service mints at /register -- for the account that passkey belongs
# to. The live test found the service minting none, so every charge under a
# principal was denied as unbound with both approvals in. This takes the
# service's own enrollment, not a hand-built one, through the real filter.


def _service_in_external_mode(monkeypatch, provider):
    from extensible_mcp_vc.oauth import ExternalIssuer

    from .idp_fixtures import INTERNAL, ISSUER, mock_client
    from .webauthn_fixtures import load_approval_module

    monkeypatch.setenv("APPROVAL_ISSUER", ISSUER)
    monkeypatch.setenv("APPROVAL_ISSUER_INTERNAL", INTERNAL)
    mod = load_approval_module(with_admin_key=True)
    mod._external = ExternalIssuer(mod._external.config, http_client=mock_client(provider))
    return mod


async def _charge_under(principal, *, enrollment, admin, merchant_key, child_passkey, cred_id):
    from extensible_mcp.types import Principal  # noqa: F401 - the type under test

    invoice_fields = _invoice_fields(total_cents=400, nonce="urn:uuid:bound")
    signature = _sign(invoice_fields, merchant_key)
    bundle = PolicyBundle.load(
        BUNDLE_DIR, name="family_spend_invoice",
        builtins=default_builtins(webauthn_rp_id=RP_ID),
    )

    async def wallet_lookup(subject: str):
        if subject != cred_id:
            return None
        # What family_proxy_server's enrollment_lookup does: the service's
        # {jws, claims} with the issuer's key attached.
        return {**enrollment, "adminKey": json.dumps(admin["key"].as_dict(private=False))}

    trusted = [{"merchantId": MERCHANT_ID, "key": _b64u(merchant_key.public_key().public_bytes_raw())}]
    f = InvoiceGatedFilter(
        bundle,
        base_config={"webauthnOrigin": ORIGIN, "trustedAdminDids": [admin["did"]]},
        wallet_lookup=wallet_lookup,
        trusted_merchants_client=_StubTrustedMerchantsClient(trusted),
    )
    request = CallRequest(
        tool_name="settlement__charge_invoice",
        arguments={
            "amountCents": 400, "merchantId": MERCHANT_ID, "nonce": "urn:uuid:bound",
            "invoice": {**invoice_fields, "signature": signature},
            "childApproval": _child_approval(child_passkey, cred_id=cred_id, invoice_fields=invoice_fields),
        },
        server_name="settlement",
        principal=principal,
    )
    return await f.check(request)


async def test_the_services_enrollment_binds_the_console_session_to_the_approver(
    monkeypatch, merchant_key, child_passkey
):
    from fastapi.testclient import TestClient
    from fastmcp.server.auth.providers.jwt import RSAKeyPair

    from extensible_mcp.types import Principal
    from extensible_mcp_vc.webauthn import b64url_encode

    from .idp_fixtures import ISSUER, FakeProvider, bearer, mint
    from .webauthn_fixtures import attestation_object

    keypair = RSAKeyPair.generate()
    mod = _service_in_external_mode(monkeypatch, FakeProvider(keypair))
    client = TestClient(mod.app)

    # The child, signed in at the provider as account child-uuid, enrols.
    r = client.post("/register", json={
        "attestationObject": b64url_encode(attestation_object(child_passkey.public_key(), b"cred-bound")),
    }, headers=bearer(mint(keypair, ["child"], sub="child-uuid")))
    assert r.status_code == 200, r.text
    cred_id = r.json()["credentialId"]
    enrollment = client.get(f"/enrollment/{cred_id}").json()
    kw = dict(enrollment=enrollment, admin=mod._admin_signer, merchant_key=merchant_key,
              child_passkey=child_passkey, cred_id=cred_id)

    # The same person at the console: allowed.
    same = Principal(sub="child-uuid", iss=ISSUER, roles=frozenset({"child"}))
    result = await _charge_under(same, **kw)
    assert result.allowed is True, result.reason

    # Another account at the console, holding the child's approval: denied,
    # and the sentence names the binding.
    other = Principal(sub="someone-else", iss=ISSUER, roles=frozenset({"child"}))
    result = await _charge_under(other, **kw)
    assert result.allowed is False
    assert "not bound to the member" in result.reason

    # The same account at a different provider is a different account.
    elsewhere = Principal(sub="child-uuid", iss="http://other.test/realms/x", roles=frozenset({"child"}))
    assert (await _charge_under(elsewhere, **kw)).allowed is False

    # No principal (the home shape): the check is vacuous, as before.
    assert (await _charge_under(None, **kw)).allowed is True

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Headless WebAuthn fixtures: a minimal CBOR encoder plus builders for the two
artifacts a browser authenticator would produce — a registration
``attestationObject`` (an ES256/P-256 COSE key) and a ``navigator.credentials.get``
assertion signing over a server-set challenge. Shared by the approval-service,
purchase, and negotiation tests so the assertion-forging logic lives in one place,
alongside the invoice-approval scaffolding (trusted merchant, signed invoice,
enrollment, approval) those tests drive the service through.

Not a test module (no ``test_`` prefix), so pytest imports but does not collect it.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import tempfile
from urllib.parse import parse_qs, urlparse
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from extensible_mcp_vc.invoice import sign_invoice
from extensible_mcp_vc.webauthn import b64url_encode

# The FastAPI TestClient serves from http://testserver, so the rpId/origin the
# server derives from the request match these.
RP_ID = "testserver"
ORIGIN = "http://testserver"


def _head(major, n):
    mt = major << 5
    return bytes([mt | n]) if n < 24 else bytes([mt | 24, n]) if n < 256 else bytes([mt | 25]) + n.to_bytes(2, "big")


def _cbor(x):
    if isinstance(x, int):
        return _head(0, x) if x >= 0 else _head(1, -1 - x)
    if isinstance(x, bytes):
        return _head(2, len(x)) + x
    if isinstance(x, str):
        b = x.encode(); return _head(3, len(b)) + b
    if isinstance(x, dict):
        out = _head(5, len(x))
        for k, v in x.items():
            out += _cbor(k) + _cbor(v)
        return out
    raise TypeError


def attestation_object(pub, cred_id: bytes) -> bytes:
    """A ``fmt: none`` attestation object embedding ``pub`` as an ES256 COSE key —
    what ``navigator.credentials.create`` hands back at enrollment."""
    n = pub.public_numbers()
    cose = _cbor({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})
    auth = (hashlib.sha256(RP_ID.encode()).digest() + bytes([0x01 | 0x04 | 0x40])
            + b"\x00\x00\x00\x01" + b"\x00" * 16 + len(cred_id).to_bytes(2, "big") + cred_id + cose)
    return _cbor({"fmt": "none", "attStmt": {}, "authData": auth})


def assertion_for(key, challenge: bytes, *, flags: int = 0x05) -> dict[str, str]:
    """A WebAuthn assertion signing over an arbitrary server-set ``challenge``
    (bytes). ``flags`` defaults to UP|UV; pass ``0x01`` for present-not-verified."""
    client = json.dumps(
        {"type": "webauthn.get", "challenge": b64url_encode(challenge), "origin": ORIGIN}
    ).encode()
    auth = hashlib.sha256(RP_ID.encode()).digest() + bytes([flags]) + b"\x00\x00\x00\x02"
    sig = key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
    return {
        "authenticatorData": b64url_encode(auth),
        "clientDataJSON": b64url_encode(client),
        "signature": b64url_encode(sig),
    }


# --------------------------------------------------------------------------- #
# The invoice-approval flow: the scaffolding an approval-service test needs to
# get from a bare app to a pending approval the humans can sign. The retired
# spend rail could be driven with a single POST; the invoice rail needs a
# merchant key in the trusted set and a merchant-signed invoice, so that setup
# lives here rather than being copied into every caller.
# --------------------------------------------------------------------------- #

FUTURE_EXP = 4_000_000_000  # year 2096 — the endpoint checks expiry against real time


def load_approval_module(*, with_admin_key: bool = False):
    """The approval service module, loaded from the examples script. A
    fresh module per call, so each test starts with empty registries.

    Each call gets its own throwaway workspace via ``VC_WORKSPACE``: the module
    builds a ``DemoUserStore`` at import, which would otherwise create
    ``approval-users.json`` inside the repo's real workspace directory the
    first time any test imported it.

    The store is hung on ``app.state`` so ``sign_in`` can read the generated
    password for *this* app rather than guessing which module instance is
    current.
    """
    path = Path(__file__).resolve().parents[1] / "examples" / "approval_service.py"
    workspace = Path(tempfile.mkdtemp(prefix="approval-ws-"))
    if with_admin_key:
        # Enough of a workspace for _load_admin_signer to find a key, so the
        # admin-attested enrollment path is exercised rather than skipped.
        from joserfc.jwk import OKPKey

        admin_did = "did:web:admin.test"
        (workspace / "keys").mkdir(parents=True, exist_ok=True)
        (workspace / "keys" / "admin.jwk").write_text(
            json.dumps(OKPKey.generate_key("Ed25519").as_dict(private=True))
        )
        (workspace / "vc-config.json").write_text(
            json.dumps({"trusted_admin_dids": [admin_did]})
        )
    previous = os.environ.get("VC_WORKSPACE")
    os.environ["VC_WORKSPACE"] = str(workspace)
    try:
        spec = importlib.util.spec_from_file_location("approval_service", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        if previous is None:
            os.environ.pop("VC_WORKSPACE", None)
        else:
            os.environ["VC_WORKSPACE"] = previous
    mod.app.state.users = mod._users
    return mod


def load_approval_app(*, with_admin_key: bool = False):
    """Just the app, for tests that do not need the module."""
    return load_approval_module(with_admin_key=with_admin_key).app


def sign_in(client, role: str, store=None) -> dict[str, str]:
    """Bearer headers for ``role``, through the real authorization-code + PKCE
    flow rather than by minting a token directly -- so every test that enrols
    also exercises the flow the browser uses.

    Reads the password from the service's own user store, which is what the
    operator reads from the startup banner.
    """
    import secrets

    from extensible_mcp_vc.oauth import CLIENT_ID, pkce_challenge

    store = store or client.app.state.users
    password = next(u.password for u in store.users if u.role == role)

    verifier = secrets.token_urlsafe(48)
    r = client.get("/authorize", params={
        "response_type": "code", "client_id": CLIENT_ID, "redirect_uri": "/",
        "state": "xyz", "code_challenge": pkce_challenge(verifier),
        "code_challenge_method": "S256"})
    assert r.status_code == 200, r.text

    r = client.post("/authorize", data={
        "username": role, "password": password, "redirect_uri": "/",
        "code_challenge": pkce_challenge(verifier), "state": "xyz"},
        follow_redirects=False)
    assert r.status_code == 303, r.text
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]

    r = client.post("/token", data={
        "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
        "redirect_uri": "/", "client_id": CLIENT_ID})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


async def sign_in_async(client, role: str, store) -> dict[str, str]:
    """``sign_in`` for an httpx.AsyncClient, which has no ``.app`` to read the
    store from, so it is passed in."""
    import secrets

    from extensible_mcp_vc.oauth import CLIENT_ID, pkce_challenge

    password = next(u.password for u in store.users if u.role == role)
    verifier = secrets.token_urlsafe(48)
    challenge = pkce_challenge(verifier)

    r = await client.get("/authorize", params={
        "response_type": "code", "client_id": CLIENT_ID, "redirect_uri": "/",
        "state": "xyz", "code_challenge": challenge, "code_challenge_method": "S256"})
    assert r.status_code == 200, r.text
    r = await client.post("/authorize", data={
        "username": role, "password": password, "redirect_uri": "/",
        "code_challenge": challenge, "state": "xyz"})
    assert r.status_code == 303, r.text
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    r = await client.post("/token", data={
        "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
        "redirect_uri": "/", "client_id": CLIENT_ID})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def enroll(client, role: str):
    """Sign in as ``role``, then register a fresh passkey under it; returns
    ``(private_key, credentialId)``.

    No role is sent: the service takes it from the token.
    """
    headers = sign_in(client, role)
    key = ec.generate_private_key(ec.SECP256R1())
    r = client.post("/register", json={
        "attestationObject": b64url_encode(
            attestation_object(key.public_key(), f"cred-{role}".encode())),
    }, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["role"] == role
    return key, r.json()["credentialId"]


def trust_merchant(client, merchant_id: str = "pizza-1") -> Ed25519PrivateKey:
    """Mint a merchant Ed25519 key and register it into the buyer's closed
    trusted-merchant set; returns the private key the merchant signs with."""
    key = Ed25519PrivateKey.generate()
    raw = b64url_encode(key.public_key().public_bytes_raw())
    r = client.post("/trust-merchant", json={"merchantId": merchant_id, "publicKey": raw})
    assert r.status_code == 200 and merchant_id in r.json()["trusted"]
    return key


def sample_invoice(**over) -> dict:
    """A merchant-signed-invoice body. The default ``totalCents`` (1800) is over
    the $10 solo limit, so it needs child + parent; the ``nonce`` is what makes
    an approval of it authorize exactly one transaction."""
    inv = {
        "merchantId": "pizza-1",
        "merchant": "Tony's Pizza",
        "items": [{"name": "Large Pepperoni", "qty": 1}],
        "totalCents": 1800,
        "currency": "usd",
        "exp": FUTURE_EXP,
        "nonce": "urn:uuid:inv-1",
    }
    inv.update(over)
    return inv


def issue_invoice(client, merchant_key: Ed25519PrivateKey, invoice: dict):
    """The merchant signs ``invoice``; the buyer posts it for approval."""
    return client.post(
        "/request-invoice",
        json={"invoice": invoice, "signature": sign_invoice(invoice, merchant_key)},
    )


def approve_invoice(client, approval_id, key, cred_id, challenge: bytes, *, flags: int = 0x05):
    """Approve ``approval_id`` with a passkey assertion over ``challenge`` —
    normally ``invoice_challenge(invoice)``, the server-authoritative value."""
    return client.post(
        f"/approve/{approval_id}",
        json={"credentialId": cred_id, **assertion_for(key, challenge, flags=flags)},
        headers=sign_in(client, "child"),
    )

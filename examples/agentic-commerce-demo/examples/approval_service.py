# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""A WebAuthn approval service: enroll principals, then have each approve a
specific action with a biometric — bound cryptographically to that exact action.

This is the phone-approval surface from the build direction (NOTES.md Layer 3),
built on plain WebAuthn: a browser page shows the human-readable action and an
"Approve" button; the platform authenticator (Face ID / fingerprint / Windows
Hello) signs over a challenge the *server* set to ``hash(action)``; the server
verifies the assertion and that the signed challenge matches the action it is
authorizing. A manipulated agent could carry the resulting evidence but could
neither forge it nor point it at a different action.

**Multi-party.** An action's *required roles* are derived from its amount,
mirroring the family-spend policy's tiering: at or under the $10 solo limit it needs
only the ``child``; above it, both ``child`` and ``parent``. Each required
principal signs over the *same* action hash; the action is authorized only once
every required role has approved. This is the multi-party composition — N humans
each consenting to the exact action — modeled on the approval surface. (The
request-then-authorization *chaining*, where the parent authorizes the child's
specific request, is the VC-layer refinement; here both simply approve the
action, which is the clean demonstration of multi-party consent.)

Scope: enrollment + multi-party approval end to end, verifiable in a browser on
localhost and, headless, by ``tests/test_approval_service.py``. Deferred to a
native-app release: WYSIWYS — that each human *saw* the true action in a trusted
surface, not just that the signature binds it. The server holds the action
authoritatively and binds to it, so the agent-forgery threat is fully closed;
only page-display trust waits for the app.

Running it on one laptop (development / multi-principal demo)
------------------------------------------------------------
    uv run python examples/approval_service.py      # -> http://localhost:7500

Open two browser windows. In window A, set the role to ``child`` and enroll; in
window B, set it to ``parent`` and enroll (each enrollment mints a distinct
credential). Request an over-$10 approval in either window, then click Approve
in each — the status area shows it complete only once both have signed. On one
laptop the same Touch ID stands in for both principals; that demonstrates the
mechanism (distinct keys, roles, and action-bound approvals composed), not two
distinct human identities. Two hardware security keys, or two devices, give
genuinely separate authenticators.

Running it for a phone demo (real Face ID / fingerprint)
--------------------------------------------------------
A phone cannot reach your laptop's ``localhost``, and WebAuthn refuses any
non-HTTPS, non-localhost origin — so you need HTTPS with a valid cert and a real
domain. You do **not** need AWS/Azure; a tunnel to this laptop service is the
fast path:

    uv run python examples/approval_service.py       # terminal 1
    ngrok http 7500                                  # terminal 2  (or: cloudflared tunnel --url http://localhost:7500)

Open the ``https://<something>.ngrok-free.app`` URL it prints on your phone.
WebAuthn works (valid cert + real domain), and everything still runs on your
laptop. The page uses ``location.hostname`` as the WebAuthn rpId, so it adapts
to the tunnel host automatically. Caveat: credentials are bound to that exact
hostname — a *random* ngrok subdomain changes between sessions and invalidates
earlier enrollments, so use a reserved/custom subdomain (or Cloudflare Tunnel
with your own domain) for a repeatable demo. A real cloud host (Fly.io / Render
are far easier than raw AWS/Azure) is only needed when you want it always-on.
"""

from __future__ import annotations

import asyncio
import base64
import html
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from extensible_mcp_vc.oauth import (
    AUDIENCE,
    CLIENT_ID,
    AuthorizationServer,
    DemoUserStore,
    OAuthError,
)
from extensible_mcp_vc.invoice import (
    InvoiceError,
    invoice_challenge,
    public_key_from_raw,
    verify_invoice,
)
from extensible_mcp_vc.settlement import (
    PaymentDeclined,
    executor_from_env,
    settle,
)
from extensible_mcp_vc.webauthn import (
    WebAuthnError,
    b64url_encode,
    parse_registration,
    verify_webauthn_assertion,
)

app = FastAPI(title="WebAuthn approval service")

# The family-spend policy's solo limit: at/under this, only the child is required.
_SOLO_LIMIT_CENTS = 1000

# Demo state (in-memory). credential_id(b64url) -> {"key", "role"}.
_credentials: dict[str, dict[str, Any]] = {}
# approval_id -> {kind, subject, challenge(bytes), required_roles, approvals, status}.
# `kind` is "action" (a raw self-asserted spend) or "invoice" (a merchant-signed
# invoice the approvals bind to); `challenge` is what the WebAuthn assertion must
# sign, so both flows share /approve.
_pending: dict[str, dict[str, Any]] = {}
_latest_id: str | None = None
# merchantId -> Ed25519 public key; the closed set of merchants the buyer will
# transact with (mirrors the trusted-admin set for the humans' memberships).
_trusted_merchants: dict[str, Ed25519PublicKey] = {}

# The settlement authority: once an invoice is fully approved, this service (the
# party that verified the human consent) charges the rail for the invoice's terms
# and signs a receipt with this key. The rail is chosen by SETTLEMENT=mock|stripe.
# The private key never leaves this process; its public half (below) is what the
# merchant registers to trust receipts.
_settlement_key = Ed25519PrivateKey.generate()
_SETTLEMENT_PUBLIC = b64url_encode(_settlement_key.public_key().public_bytes_raw())
_executor = executor_from_env()

# --------------------------------------------------------------------------- #
# Admin-attested enrollment (the wallet rail's production binding)
#
# When the family admin's signing key is available (the household-identity
# workspace), each registration also mints an **admin-signed enrollment VC**
# binding credentialId -> (role, publicKey) — the revocable delegation the
# family_spend_webauthn policy verifies via `enrolled_as`. Without the key
# the service still runs in its original self-enrollment mode (the standalone
# demo and its tests), it just serves no /enrollment lookups.
# --------------------------------------------------------------------------- #

_WORKSPACE = Path(os.environ.get(
    "VC_WORKSPACE", str(Path(__file__).resolve().parent.parent / "workspace")
))
_ENROLLMENT_TTL_SECONDS = 30 * 24 * 3600

# credential_id(b64url) -> {"jws", "claims"} — the admin-signed enrollment VC.
_enrollments: dict[str, dict[str, Any]] = {}


def _load_admin_signer():
    """The admin's private JWK + DID from the workspace, or ``None``."""
    key_path = _WORKSPACE / "keys" / "admin.jwk"
    cfg_path = _WORKSPACE / "vc-config.json"
    if not (key_path.exists() and cfg_path.exists()):
        return None
    from joserfc.jwk import OKPKey

    key = OKPKey.import_key(json.loads(key_path.read_text()))
    did = json.loads(cfg_path.read_text())["trusted_admin_dids"][0]
    return {"key": key, "did": did}


_admin_signer = _load_admin_signer()

# Enrollment mints an admin-signed "this key holds role X", so it needs an
# identity to derive X from. Passwords are random per workspace and printed at
# startup; see oauth.py for why a real flow rather than a password check, and
# why not a fixed pair.
_users = DemoUserStore(_WORKSPACE)
_auth = AuthorizationServer(users=_users)


def _require_token(request: Request) -> dict[str, Any]:
    """Claims for the caller's bearer token, or a 401 the browser can act on.

    Enforced on the *endpoint*, not on page delivery: the threat is a process
    that never loads the page and POSTs straight here.
    """
    try:
        return _auth.verify_token(request.headers.get("Authorization"))
    except OAuthError as e:
        raise HTTPException(
            401, f"{e.code}: {e.description}",
            headers={"WWW-Authenticate": 'Bearer realm="approval"'},
        ) from e


def _p256_jwk_string(public_key) -> str:
    nums = public_key.public_numbers()
    return json.dumps(
        {"kty": "EC", "crv": "P-256",
         "x": b64url_encode(nums.x.to_bytes(32, "big")),
         "y": b64url_encode(nums.y.to_bytes(32, "big"))}
    )


def _mint_enrollment_vc(cred_id_b64: str, role: str, public_key) -> dict[str, Any]:
    from joserfc import jws as joserfc_jws

    now = int(time.time())
    claims = {
        "iss": _admin_signer["did"],
        "sub": cred_id_b64,
        "nbf": now - 60,
        "exp": now + _ENROLLMENT_TTL_SECONDS,
        "vc": {"credentialSubject": {
            "role": role, "publicKey": _p256_jwk_string(public_key)}},
    }
    token = joserfc_jws.serialize_compact(
        {"alg": "Ed25519"}, json.dumps(claims).encode(),
        _admin_signer["key"], algorithms=["Ed25519"],
    )
    return {"jws": token, "claims": claims}


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _rp_id(request: Request) -> str:
    return request.url.hostname or "localhost"


def _origin(request: Request) -> str:
    return f"{request.url.scheme}://{request.headers.get('host', request.url.netloc)}"


def _required_roles_for(amount_cents: int) -> list[str]:
    return ["child"] if amount_cents <= _SOLO_LIMIT_CENTS else ["child", "parent"]


def _log_event(p: dict[str, Any], label: str) -> None:
    p.setdefault("events", []).append({"t": int(time.time()), "label": label})


def _new_pending(kind: str, subject: dict[str, Any], challenge: bytes,
                 amount_cents: int) -> str:
    global _latest_id
    approval_id = str(uuid.uuid4())
    _pending[approval_id] = {
        "kind": kind,
        "subject": subject,
        "challenge": challenge,
        "required_roles": _required_roles_for(amount_cents),
        "approvals": {},
        "status": "pending",
        "created": int(time.time()),
    }
    _latest_id = approval_id
    return approval_id


def _summary(approval_id: str, p: dict[str, Any]) -> dict[str, Any]:
    out = {
        "id": approval_id,
        "required_roles": p["required_roles"],
        "approved_roles": sorted(p["approvals"]),
        "remaining_roles": [r for r in p["required_roles"] if r not in p["approvals"]],
        "status": p["status"],
        "challenge": b64url_encode(p["challenge"]),
    }
    out[p["kind"]] = p["subject"]  # "action" or "invoice"
    if "receipt" in p:  # present once settled; public signed evidence for the merchant
        out["receipt"] = p["receipt"]
        out["receipt_signature"] = p["receipt_signature"]
    if "settlement_error" in p:
        out["settlement_error"] = p["settlement_error"]
    return out


def _settle_if_ready(p: dict[str, Any]) -> None:
    """Charge the rail for the invoice's terms and store the signed receipt.
    Only the signed-invoice flow settles — it is the one carrying the
    merchant/nonce a receipt commits to. Idempotent (a no-op once a receipt
    is already recorded), so the explicit ``/settle`` endpoint can be safely
    retried. Triggered explicitly by ``/settle`` — see that endpoint for why
    this is no longer an automatic side effect of ``/approve``."""
    if p["status"] != "approved" or p["kind"] != "invoice" or "receipt" in p:
        return
    try:
        receipt, signature = settle(
            p["subject"], executor=_executor, settlement_key=_settlement_key
        )
    except PaymentDeclined as e:
        p["settlement_error"] = str(e)  # stays "approved"; can be retried
        _log_event(p, f"payment DECLINED: {e}")
        return
    p["receipt"], p["receipt_signature"] = receipt, signature
    p["status"] = "settled"
    _log_event(p, f"settled on the {receipt.get('status', 'paid')} rail "
                  f"(receipt {receipt.get('paymentRef')}, receipt signed)")


@app.post("/register")
async def register(request: Request) -> JSONResponse:
    """Enrol a passkey under the authenticated caller's role.

    The role comes from the token and any ``role`` in the body is ignored. A
    caller who could name its own role would self-assign authority and the
    admin would sign it, which is the whole reason this endpoint is
    authenticated -- authenticating the requester while still believing the
    body would close nothing.
    """
    claims = _require_token(request)
    body = await request.json()
    try:
        cred_id, public_key = parse_registration(
            _b64url_decode(body["attestationObject"])
        )
    except (WebAuthnError, KeyError, ValueError) as e:
        raise HTTPException(400, f"registration failed: {e}") from e
    cred_id_b64 = b64url_encode(cred_id)
    role = claims["role"]
    _credentials[cred_id_b64] = {"key": public_key, "role": role}
    if _admin_signer is not None:
        _enrollments[cred_id_b64] = _mint_enrollment_vc(cred_id_b64, role, public_key)
    return JSONResponse(
        {"credentialId": cred_id_b64, "role": role,
         "adminAttested": _admin_signer is not None}
    )


@app.get("/enrollment/{credential_id}")
async def enrollment(credential_id: str) -> JSONResponse:
    """The admin-signed enrollment VC for a passkey — the proxy's
    ``approverEnrollment`` wallet-source, keyed by ``approval.credentialId``."""
    e = _enrollments.get(credential_id)
    if e is None:
        raise HTTPException(404, "no enrollment VC for this credential")
    return JSONResponse(e)


@app.get("/settlement-card")
async def settlement_card() -> JSONResponse:
    """The settlement authority's public key; a merchant registers this to trust
    the payment receipts this service signs. ``publicKey`` is base64url raw Ed25519."""
    return JSONResponse({"publicKey": _SETTLEMENT_PUBLIC})


@app.post("/trust-merchant")
async def trust_merchant(request: Request) -> JSONResponse:
    """Register a merchant into the buyer's closed trusted set (config, really —
    an endpoint here for the demo). `publicKey` is base64url raw Ed25519."""
    body = await request.json()
    _trusted_merchants[body["merchantId"]] = public_key_from_raw(body["publicKey"])
    return JSONResponse({"trusted": sorted(_trusted_merchants)})


@app.get("/trusted-merchants")
async def trusted_merchants() -> JSONResponse:
    """The current trusted-merchant set, as the certified
    ``family_spend_invoice`` policy's own fetch plan expects it: a *list*
    of ``{merchantId, key}`` entries, not a keyed map (the certified
    fragment has no dynamic key projection). Fetched live by
    the proxy's ``InvoiceGatedFilter`` on every gated call rather than
    snapshotted once at startup, since trust here is established
    dynamically (boot-time trust exchange, or later additions) and a
    stale snapshot would silently deny a merchant trusted after the proxy
    started."""
    return JSONResponse([
        {"merchantId": merchant_id, "key": b64url_encode(key.public_bytes_raw())}
        for merchant_id, key in _trusted_merchants.items()
    ])


@app.post("/request-invoice")
async def request_invoice(request: Request) -> JSONResponse:
    """Request approval of a **merchant-signed invoice**. The invoice is verified
    against the trusted-merchant set first; the human approvals then bind to the
    invoice, not to any buyer-agent account of a negotiation."""
    body = await request.json()
    invoice = body["invoice"]
    try:
        verify_invoice(invoice, body["signature"], trusted_merchants=_trusted_merchants)
    except InvoiceError as e:
        raise HTTPException(400, f"invoice rejected: {e}") from e
    approval_id = _new_pending(
        "invoice", invoice, invoice_challenge(invoice), int(invoice["totalCents"])
    )
    p = _pending[approval_id]
    p["subject_signature"] = body["signature"]
    _log_event(p, f"invoice received from {invoice.get('merchant')} "
                  f"(${int(invoice['totalCents'])/100:.2f}, merchant signature verified)")
    return JSONResponse(_summary(approval_id, p))


@app.post("/settle")
async def settle_invoice(request: Request) -> JSONResponse:
    """Execute settlement for an already-approved invoice, identified by its
    ``nonce`` — the invoice's own per-invoice identifier, the same key
    ``/commitment`` matches fulfillment on. Called only after the certified
    ``family_spend_invoice`` policy has independently verified the
    merchant's signature, the invoice-to-call binding, and every required
    passkey approval — this endpoint does not re-decide authorization, it
    only executes (and stays fail-closed on its own narrower "is this
    actually approved" check as defense-in-depth, in case it is ever
    reachable some other way).

    ``merchantId``/``amountCents`` are still supplied and still checked,
    but as a cross-check on the record the nonce selected rather than as
    the selector. Selecting on those two alone was ambiguous: two approved
    invoices from one merchant for the same total resolved to whichever was
    created most recently, so the policy could verify invoice A and this
    endpoint charge and receipt invoice B."""
    body = await request.json()
    merchant_id, amount_cents = body.get("merchantId"), body.get("amountCents")
    nonce = body.get("nonce")
    if not nonce:
        raise HTTPException(400, "settlement requires the invoice's nonce")
    match = next(
        (
            (aid, v) for aid, v in _pending.items()
            if v["kind"] == "invoice" and v["subject"].get("nonce") == nonce
        ),
        None,
    )
    if match is None:
        raise HTTPException(404, f"no invoice here with nonce {nonce!r}")
    approval_id, p = match
    subject = p["subject"]
    if (
        subject.get("merchantId") != merchant_id
        or subject.get("totalCents") != amount_cents
    ):
        raise HTTPException(
            400,
            f"invoice {nonce!r} is for merchant {subject.get('merchantId')!r} at "
            f"${(subject.get('totalCents') or 0) / 100:.2f}, not "
            f"{merchant_id!r} at ${(amount_cents or 0) / 100:.2f}",
        )
    if p["status"] not in ("approved", "settled"):
        raise HTTPException(400, f"invoice is not yet approved (status: {p['status']!r})")
    # settle() drives a synchronous payment rail (Stripe's SDK, over the
    # network). Run inline it blocked the whole service for the duration of
    # the charge -- including the /pending polls the approval page lives on,
    # so the browser appeared to hang while a payment went through.
    await asyncio.to_thread(_settle_if_ready, p)
    if "receipt" not in p:
        raise HTTPException(400, p.get("settlement_error", "settlement failed"))
    return JSONResponse(_summary(approval_id, p))


@app.get("/pending")
async def latest_pending() -> JSONResponse:
    if _latest_id is None:
        raise HTTPException(404, "no approval requested yet")
    return JSONResponse(_summary(_latest_id, _pending[_latest_id]))


@app.get("/pending/{approval_id}")
async def pending(approval_id: str) -> JSONResponse:
    p = _pending.get(approval_id)
    if p is None:
        raise HTTPException(404, "unknown approval")
    return JSONResponse(_summary(approval_id, p))


@app.post("/approve/{approval_id}")
async def approve(approval_id: str, request: Request) -> JSONResponse:
    # The assertion already proves possession of an enrolled key, so this is
    # defence in depth rather than the load-bearing check -- but an approval
    # surface that anything on the network can POST to is not one either.
    _require_token(request)
    p = _pending.get(approval_id)
    if p is None:
        raise HTTPException(404, "unknown approval")
    body = await request.json()
    cred = _credentials.get(body.get("credentialId", ""))
    if cred is None:
        raise HTTPException(400, "unknown credential — enroll this device first")
    role = cred["role"]
    if role not in p["required_roles"]:
        raise HTTPException(
            400, f"role {role!r} is not required here (needs {p['required_roles']})"
        )
    try:
        verify_webauthn_assertion(
            public_key=cred["key"],
            authenticator_data=_b64url_decode(body["authenticatorData"]),
            client_data_json=_b64url_decode(body["clientDataJSON"]),
            signature=_b64url_decode(body["signature"]),
            expected_challenge=p["challenge"],  # server-authoritative (action or invoice)
            expected_origin=_origin(request),
            expected_rp_id=_rp_id(request),
        )
    except WebAuthnError as e:
        raise HTTPException(400, f"approval rejected: {e}") from e
    p["approvals"][role] = body["credentialId"]
    _log_event(p, f"{role} approved with passkey (assertion bound to these exact terms)")
    # Retain the raw assertion: on the wallet rail the policy is the authority,
    # so the proxy needs the four fields as `input.approval` (base64url,
    # verbatim as the browser produced them).
    p.setdefault("assertions", {})[role] = {
        "credentialId": body["credentialId"],
        "authenticatorData": body["authenticatorData"],
        "clientDataJSON": body["clientDataJSON"],
        "signature": body["signature"],
    }
    if all(r in p["approvals"] for r in p["required_roles"]):
        p["status"] = "approved"
        # Settlement is no longer an automatic side effect of full approval —
        # see /settle. For the "action" kind (raw self-asserted spend) there
        # was never a settlement step here at all; this just stops the
        # "invoice" kind from being the one exception.
    return JSONResponse(_summary(approval_id, p))


@app.get("/assertion/{approval_id}/{role}")
async def assertion(approval_id: str, role: str) -> JSONResponse:
    """The retained WebAuthn assertion a role signed for an approval — what
    the proxy passes as the policy's ``approval`` input."""
    p = _pending.get(approval_id)
    if p is None:
        raise HTTPException(404, "unknown approval")
    a = (p.get("assertions") or {}).get(role)
    if a is None:
        raise HTTPException(404, f"role {role!r} has not approved this action yet")
    return JSONResponse(a)


@app.post("/commitment")
async def record_commitment(request: Request) -> JSONResponse:
    """The chain's last link: the merchant-signed fulfillment commitment,
    verified against the trusted-merchant set and matched by nonce to the
    settled invoice it fulfills."""
    body = await request.json()
    commitment, signature = body.get("commitment") or {}, body.get("signature", "")
    nonce = commitment.get("nonce")
    p = next(
        (v for v in _pending.values()
         if v["kind"] == "invoice" and v["subject"].get("nonce") == nonce),
        None,
    )
    if p is None:
        raise HTTPException(404, f"no invoice here with nonce {nonce!r}")
    try:
        verify_invoice(commitment, signature, trusted_merchants=_trusted_merchants)
    except InvoiceError as e:
        raise HTTPException(400, f"commitment rejected: {e}") from e
    p["commitment"], p["commitment_signature"] = commitment, signature
    p["status"] = "fulfilled"
    eta = commitment.get("etaMinutes")
    _log_event(p, f"merchant committed to fulfil (signed; eta {eta} min)")
    return JSONResponse({"ok": True})


@app.get("/audit.json")
async def audit_json() -> JSONResponse:
    """The evidence chains, newest first — what an auditor (or an audience)
    sees. Raw assertions and challenges stay out; presence and verification
    outcomes are the story."""
    out = []
    for approval_id, p in sorted(
        _pending.items(), key=lambda kv: kv[1].get("created", 0), reverse=True
    ):
        entry = {
            "id": approval_id,
            "kind": p["kind"],
            "status": p["status"],
            "created": p.get("created"),
            "subject": p["subject"],
            "required_roles": p["required_roles"],
            "approved_roles": sorted(p["approvals"]),
            "events": p.get("events", []),
            "signatures": {},
        }
        if p.get("subject_signature"):
            entry["signatures"]["merchant"] = p["subject_signature"][:16] + "…"
        if p.get("receipt"):
            entry["receipt"] = {
                "paymentRef": p["receipt"].get("paymentRef"),
                "status": p["receipt"].get("status"),
            }
            entry["signatures"]["settlement"] = p["receipt_signature"][:16] + "…"
        if p.get("settlement_error"):
            entry["settlement_error"] = p["settlement_error"]
        if p.get("commitment"):
            entry["commitment"] = {
                "etaMinutes": p["commitment"].get("etaMinutes"),
                "deliverTo": p["commitment"].get("deliverTo"),
                "paymentRef": p["commitment"].get("paymentRef"),
            }
            entry["signatures"]["fulfillment"] = p["commitment_signature"][:16] + "…"
        out.append(entry)
    return JSONResponse(out)


@app.get("/audit")
async def audit_page() -> HTMLResponse:
    return HTMLResponse(_AUDIT_PAGE)


_AUDIT_PAGE = """<!doctype html><meta charset=utf-8>
<title>Evidence chains</title>
<style>body{font:15px system-ui;max-width:52em;margin:2em auto;padding:0 1em;background:#fafaf7}
h1{font-size:1.3em}.card{background:#fff;border:1px solid #ddd;border-radius:10px;padding:1em 1.2em;margin:1em 0;box-shadow:0 1px 3px #0001}
.chain{display:flex;flex-wrap:wrap;gap:.4em;align-items:center;margin:.6em 0}
.link{padding:.3em .7em;border-radius:999px;font-size:.85em;border:1px solid #ccc;color:#999;background:#f4f4f4}
.done{background:#e7f6ec;border-color:#2a7;color:#1a5c38;font-weight:600}
.fail{background:#fdecec;border-color:#c33;color:#8a1f1f;font-weight:600}
.arrow{color:#bbb}.terms{font-size:.92em;color:#333;margin:.3em 0}
.events{font:12.5px ui-monospace,monospace;color:#666;margin:.6em 0 0;padding-left:1em}
.sig{font:11.5px ui-monospace,monospace;color:#999}
#empty{color:#888}</style>
<h1>Evidence chains</h1>
<p style=color:#666>Every step binds by signature, none by an agent's word:
terms (merchant) &rarr; consent (humans' passkeys) &rarr; consideration
(settlement rail) &rarr; obligation (merchant). Newest first.</p>
<div id=list></div><p id=empty>Nothing yet.</p>
<script>
const esc=s=>String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;');
function link(label, state, title){
  return '<span class="link '+state+'" title="'+esc(title||'')+'">'+esc(label)+'</span>';
}
function chain(e){
  const parts=[];
  if(e.kind==='invoice'){
    parts.push(link('terms signed: '+(e.subject.merchant||e.subject.merchantId),'done',
      'merchant signature verified at intake '+(e.signatures.merchant||'')));
  }else{
    parts.push(link('action: '+(e.subject.tool||''),'done','self-asserted action'));
  }
  for(const r of e.required_roles){
    const ok=e.approved_roles.includes(r);
    parts.push(link(r+(ok?' \\u2713':' \\u2026'), ok?'done':'', ok?'passkey assertion bound to these exact terms':'awaiting passkey'));
  }
  if(e.settlement_error) parts.push(link('payment declined','fail',e.settlement_error));
  else parts.push(link(e.receipt?('paid: '+e.receipt.paymentRef):'payment',
    e.receipt?'done':'', e.receipt?('receipt signed by the rail '+(e.signatures.settlement||'')):''));
  if(e.kind==='invoice')
    parts.push(link(e.commitment?('committed: eta '+e.commitment.etaMinutes+'m'):'fulfillment',
      e.commitment?'done':'', e.commitment?('merchant-signed commitment '+(e.signatures.fulfillment||'')):''));
  return parts.join('<span class=arrow>\\u2192</span>');
}
function terms(e){
  const s=e.subject;
  if(e.kind!=='invoice') return esc((s.tool||'')+' \\u2014 $'+((s.amountCents||0)/100).toFixed(2)+' at '+(s.merchant||''));
  const items=(s.items||[]).map(i=>i.qty+'\\u00d7 '+i.name).join(', ');
  return esc(items+' \\u2014 $'+((s.totalCents||0)/100).toFixed(2)
    +(s.deliverTo?(' \\u2192 '+s.deliverTo):''));
}
async function poll(){
  try{
    const es=await (await fetch('/audit.json')).json();
    document.getElementById('empty').style.display=es.length?'none':'';
    document.getElementById('list').innerHTML=es.map(e=>
      '<div class=card><div class=terms>'+terms(e)+'</div><div class=chain>'+chain(e)+'</div>'
      +'<ul class=events>'+e.events.map(ev=>{
        const t=new Date(ev.t*1000).toLocaleTimeString();
        return '<li>'+t+' \\u2014 '+esc(ev.label)+'</li>';}).join('')+'</ul></div>'
    ).join('');
  }catch(err){}
}
setInterval(poll,1500); poll();
</script>"""

_LOGIN_PAGE = """<!doctype html><meta charset=utf-8>
<title>Sign in \u2014 approval demo</title>
<style>body{font:16px system-ui;max-width:24em;margin:4em auto;padding:0 1em}
input,button{font:inherit;padding:.45em;width:100%;box-sizing:border-box;margin:.25em 0}
label{display:block;margin-top:.8em;color:#444;font-size:.9em}
.note{color:#666;font-size:.85em;margin-top:1.5em;line-height:1.5}</style>
<h1>Sign in</h1>
<p>Your role is decided by who you sign in as, not by a control on the next
page.</p>
<!--ERROR-->
<form method=post action=/authorize>
<input type=hidden name=redirect_uri value="__REDIRECT_URI__">
<input type=hidden name=code_challenge value="__CHALLENGE__">
<input type=hidden name=state value="__STATE__">
<label>Username (child or parent)<input name=username autocomplete=username autofocus></label>
<label>Password<input name=password type=password autocomplete=current-password></label>
<button type=submit>Sign in</button>
</form>
<p class=note>The credentials for this workspace were generated at startup and
printed to the service log \u2014 in the containerized demo, the live log at
:7300/logs. They are random so that reaching this page is not by itself
authority to enrol a passkey as anyone.</p>
"""

_PAGE = """<!doctype html><meta charset=utf-8>
<title>Approval demo</title>
<style>body{font:16px system-ui;max-width:42em;margin:2.5em auto;padding:0 1em}
button{font:inherit;padding:.5em 1em;margin:.3em 0;cursor:pointer}
input,select{font:inherit;padding:.3em}pre{background:#f4f4f4;padding:1em;white-space:pre-wrap}
h2{margin-top:1.4em}#status{background:#eef;padding:1em;border-radius:6px}</style>
<h1>WebAuthn approval demo</h1>
<p>Open a second window as the other role for a two-party approval.</p>
<h2>1. Enroll this window</h2>
<div>Signed in as <b id=who>\u2026</b> \u2014 this window enrols and approves as
that role.</div>
<button onclick=enroll()>Enroll with biometric</button>
<h2>2. What is pending</h2>
$<input id=amt size=6 readonly> to <input id=merch readonly>
<span style=color:#666>(&le;$10 needs child only; over $10 needs child + parent)</span>
<div style=color:#666;font-size:.9em>These mirror the invoice currently awaiting
approval — blank when there is none. Nothing here is editable: an approval
request can only be created by a merchant-signed invoice, never from this page.</div>
<h2>3. Approve the current request</h2>
<button onclick=approve()>Approve with biometric</button>
<div id=status>no request yet</div>
<h2>Log</h2><pre id=log></pre>
<script>
const log=(...a)=>document.getElementById('log').textContent=a.join(' ')+"\\n"+document.getElementById('log').textContent;
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
const unb64=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');return Uint8Array.from(atob(s),c=>c.charCodeAt(0))};
let credentialId=null, myRole=null, token=null;

// -- OAuth2 authorization code + PKCE ------------------------------------- //
// Kept in sessionStorage so a reload does not send you round the flow again,
// and so two windows can hold two different identities in one browser.
const S=sessionStorage;
const rnd=n=>b64(crypto.getRandomValues(new Uint8Array(n)));
async function s256(v){return b64(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(v)))}

async function signIn(){
  const verifier=rnd(48); S.setItem('pkce_v',verifier);
  const state=rnd(12); S.setItem('pkce_s',state);
  const q=new URLSearchParams({response_type:'code',client_id:'approval-page',
    redirect_uri:'/',state,code_challenge:await s256(verifier),code_challenge_method:'S256'});
  location.href='/authorize?'+q;
}

async function completeSignIn(){
  const u=new URL(location.href), code=u.searchParams.get('code'), state=u.searchParams.get('state');
  if(!code) return false;
  if(state!==S.getItem('pkce_s')){log('state mismatch; sign in again');return false}
  const body=new URLSearchParams({grant_type:'authorization_code',code,
    code_verifier:S.getItem('pkce_v'),redirect_uri:'/',client_id:'approval-page'});
  const r=await fetch('/token',{method:'POST',
    headers:{'content-type':'application/x-www-form-urlencoded'},body});
  if(!r.ok){log('token exchange failed');return false}
  const j=await r.json();
  S.setItem('tok',j.access_token); S.removeItem('pkce_v'); S.removeItem('pkce_s');
  history.replaceState({},'','/');   // don't leave the code in the address bar
  return true;
}

const auth=()=>({'authorization':'Bearer '+token});

async function boot(){
  await completeSignIn();
  token=S.getItem('tok');
  if(!token){await signIn();return}
  const r=await fetch('/me',{headers:auth()});
  if(r.status===401){S.removeItem('tok');await signIn();return}
  const me=await r.json(); myRole=me.role;
  document.getElementById('who').textContent=me.sub+' ('+me.role+')';
  log('signed in as',me.sub,'role',me.role);
}

async function enroll(){
  if(!token){await signIn();return}
  const c=await navigator.credentials.create({publicKey:{
    challenge:crypto.getRandomValues(new Uint8Array(32)),
    rp:{id:location.hostname,name:'Approval demo'},
    user:{id:crypto.getRandomValues(new Uint8Array(16)),name:myRole,displayName:myRole},
    pubKeyCredParams:[{type:'public-key',alg:-7}],
    authenticatorSelection:{userVerification:'required',residentKey:'preferred'},
    attestation:'none'}});
  // No role in the body: the server takes it from the token. Sending one
  // would be ignored, and relying on it is the bug this flow removes.
  const r=await fetch('/register',{method:'POST',
    headers:{'content-type':'application/json',...auth()},
    body:JSON.stringify({credentialId:b64(c.rawId),attestationObject:b64(c.response.attestationObject)})});
  if(r.status===401){log('session expired; signing in again');S.removeItem('tok');await signIn();return}
  const j=await r.json(); credentialId=j.credentialId; log('enrolled as',j.role,'('+credentialId.slice(0,10)+'\\u2026)');
}
async function approve(){
  if(!credentialId){log('enroll this window first');return}
  const pr=await fetch('/pending');
  if(!pr.ok){log('no request to approve');return}
  const cur=await pr.json();
  const s=cur.action||cur.invoice||{}; const who=s.merchant?(' at '+s.merchant):'';
  const desc='$'+((s.amountCents||0)/100).toFixed(2)+who;
  let a; try{
    a=await navigator.credentials.get({publicKey:{
      challenge:unb64(cur.challenge),rpId:location.hostname,
      allowCredentials:[{type:'public-key',id:unb64(credentialId)}],userVerification:'required'}});
  }catch(e){log('declined: '+desc);return}
  const r=await fetch('/approve/'+cur.id,{method:'POST',
    headers:{'content-type':'application/json',...auth()},
    body:JSON.stringify({credentialId,authenticatorData:b64(a.response.authenticatorData),
      clientDataJSON:b64(a.response.clientDataJSON),signature:b64(a.response.signature)})});
  const j=await r.json();
  log(r.ok?('approved '+desc+' by '+myRole+' \\u2014 '+j.status):('rejected '+desc+': '+(j.detail||JSON.stringify(j))));
}
// The amt/merch fields and the section-3 status both mirror the live
// pending request: blank when there is none, filled only while one is
// awaiting approval, and blanked again (with the resolution logged once)
// the moment it's no longer pending. /pending keeps returning the most
// recent request forever, resolved or not, so "no longer pending" has to
// be treated the same as "no request at all" here on every refresh, not
// just the very first load — never a static default that could be
// mistaken for a real request.
// firstPoll guards against replaying history into the Log pane on every
// reload: /pending has no concept of "since when", so the very first poll
// of a fresh page load would otherwise see whatever the last request still
// is (settled minutes or days ago) and log it as if it just happened. The
// fix isn't "never log the current record" — a request that's already
// pending on load and resolves moments later must still get logged, since
// that's a real live event — it's specifically "don't log whatever was
// already true before this page opened".
let lastLoggedId=null, firstPoll=true;
async function poll(){
  const amtEl=document.getElementById('amt'), merchEl=document.getElementById('merch');
  const statusEl=document.getElementById('status');
  try{
    const r=await fetch('/pending');
    if(!r.ok){amtEl.value=''; merchEl.value=''; statusEl.innerHTML='no request yet'; firstPoll=false; return}
    const j=await r.json();
    const s=j.action||j.invoice||{}; const cents=s.amountCents||s.totalCents||0;
    const who=s.merchant?(' at '+s.merchant):'';
    if(j.status==='pending'){
      amtEl.value=(cents/100).toFixed(2); merchEl.value=s.merchant||'';
      statusEl.innerHTML=
        '<b>'+j.status.toUpperCase()+'</b> \\u2014 $'+(cents/100).toFixed(2)+who
        +'<br>approved: '+(j.approved_roles.join(', ')||'none')+' &nbsp; still needs: '+(j.remaining_roles.join(', ')||'\\u2014');
    }else{
      amtEl.value=''; merchEl.value=''; statusEl.innerHTML='no request yet';
      if(j.id!==lastLoggedId){lastLoggedId=j.id;
        if(!firstPoll)log(j.status.toUpperCase()+': $'+(cents/100).toFixed(2)+who+' \\u2014 approved by '+(j.approved_roles.join(', ')||'none'));}
    }
    firstPoll=false;
  }catch(e){}
}
boot(); setInterval(poll,1500); poll();
</script>"""


# -- OAuth 2.0: authorization code + PKCE ---------------------------------- #
#
# The demo is its own authorization server. That is the point: the page speaks
# the flow a real IdP speaks, so pointing it at Entra, Keycloak, Okta or Auth0
# replaces these three endpoints with configuration instead of a rewrite.


@app.get("/authorize")
async def authorize_form(request: Request) -> HTMLResponse:
    q = request.query_params
    try:
        _auth.validate_authorization_request(
            client_id=q.get("client_id", ""),
            redirect_uri=q.get("redirect_uri", ""),
            response_type=q.get("response_type", ""),
            code_challenge=q.get("code_challenge", ""),
            code_challenge_method=q.get("code_challenge_method", ""),
        )
    except OAuthError as e:
        raise HTTPException(400, f"{e.code}: {e.description}") from e
    return HTMLResponse(
        _LOGIN_PAGE.replace("__REDIRECT_URI__", html.escape(q["redirect_uri"], quote=True))
        .replace("__CHALLENGE__", html.escape(q["code_challenge"], quote=True))
        .replace("__STATE__", html.escape(q.get("state", ""), quote=True))
    )


@app.post("/authorize")
async def authorize_submit(request: Request) -> Response:
    form = await request.form()
    try:
        _auth.validate_authorization_request(
            client_id=CLIENT_ID,
            redirect_uri=str(form.get("redirect_uri", "")),
            response_type="code",
            code_challenge=str(form.get("code_challenge", "")),
            code_challenge_method="S256",
        )
        code = _auth.issue_code(
            username=str(form.get("username", "")),
            password=str(form.get("password", "")),
            redirect_uri=str(form.get("redirect_uri", "")),
            code_challenge=str(form.get("code_challenge", "")),
        )
    except OAuthError as e:
        # Re-render rather than redirect: a failed sign-in must not hand a
        # code-shaped anything back to the client.
        return HTMLResponse(
            _LOGIN_PAGE.replace("__REDIRECT_URI__", html.escape(str(form.get("redirect_uri", "")), quote=True))
            .replace("__CHALLENGE__", html.escape(str(form.get("code_challenge", "")), quote=True))
            .replace("__STATE__", html.escape(str(form.get("state", "")), quote=True))
            .replace("<!--ERROR-->", f"<p style=color:#b00>{html.escape(e.description)}</p>"),
            status_code=401,
        )
    sep = "&" if "?" in str(form.get("redirect_uri")) else "?"
    target = f"{form.get('redirect_uri')}{sep}code={code}"
    if form.get("state"):
        target += f"&state={form.get('state')}"
    return RedirectResponse(target, status_code=303)


@app.post("/token")
async def token(request: Request) -> JSONResponse:
    form = await request.form()
    try:
        granted = _auth.exchange_code(
            code=str(form.get("code", "")),
            code_verifier=str(form.get("code_verifier", "")),
            redirect_uri=str(form.get("redirect_uri", "")),
            client_id=str(form.get("client_id", "")),
        )
    except OAuthError as e:
        return JSONResponse(
            {"error": e.code, "error_description": e.description}, status_code=400
        )
    return JSONResponse(granted, headers={"Cache-Control": "no-store"})


@app.get("/me")
async def me(request: Request) -> JSONResponse:
    """Who the token says you are. The page reads its role from here rather
    than from a control the user can set."""
    claims = _require_token(request)
    return JSONResponse({"sub": claims["sub"], "role": claims["role"]})


@app.get("/")
async def index() -> HTMLResponse:
    return HTMLResponse(_PAGE)


if __name__ == "__main__":
    # Printed on every start, because the human needs them and they are
    # random. In the containerized demo this lands in the log served at
    # :7300/logs.
    print(_users.banner(), flush=True)
    uvicorn.run(
        app,
        host=os.environ.get("APPROVAL_HOST", "127.0.0.1"),
        port=int(os.environ.get("APPROVAL_PORT", "7500")),
    )

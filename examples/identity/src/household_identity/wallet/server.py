# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""FastAPI wallet service: signs ActionRequest and ActionAuthorization VCs.

Two endpoints, both gated on human approval:

- ``POST /sign/request`` — originator mode. The caller proposes an action;
  on approval the wallet signs an ActionRequest VC.
- ``POST /sign/authorization`` — approver mode. The caller submits someone
  else's signed request; on approval the wallet signs an ActionAuthorization
  VC bound to that request by ``jti`` and content hash.

Each endpoint supports two modes:

- **Synchronous** (no ``callback_url`` in the body) — block until the human
  approves, return ``200`` with the signed bundle. Backwards-compatible with
  every caller that doesn't know about asynchronous approval.
- **Asynchronous** (``callback_url`` in the body) — enqueue the approval,
  return ``202`` with ``{"approval_id"}`` immediately, prompt the human
  in the background, and POST the bundle (or a denial) to ``callback_url``
  when it's resolved. Lets the LLM or proxy stop holding open an HTTP
  connection while a parent finds their phone.

The wallet does *not* verify request signatures on the authorization path —
that's the proxy's job. The wallet's job is to ensure a fresh authorization
is bound only to whatever the human actually saw and approved.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import uuid
from typing import Any, Awaitable, Callable

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..common import did as did_mod
from ..common import jws, vc
from .approval import prompt_terminal

ApproveFn = Callable[[str], Awaitable[bool]]

logger = logging.getLogger("household_identity.wallet")


class SignRequestBody(BaseModel):
    request_type: str
    details: dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: int = 600
    callback_url: str | None = None


class SignRequestResponse(BaseModel):
    token: str
    jti: str
    issuer: str
    membership: str | None = None


class SignAuthorizationBody(BaseModel):
    request_token: str
    scope: dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: int = 14400
    callback_url: str | None = None


class SignAuthorizationResponse(BaseModel):
    token: str
    jti: str
    issuer: str
    bound_request_jti: str
    bound_request_hash: str
    membership: str | None = None


def create_app(
    *,
    private_key: Ed25519PrivateKey,
    label: str,
    approve: ApproveFn | None = None,
    membership_token: str | None = None,
    callback_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """Build a wallet FastAPI app bound to a single Ed25519 keypair.

    ``approve`` is an async callable that receives a human-readable message
    and returns whether the user approved. Tests inject their own; the
    default wraps :func:`prompt_terminal` on a worker thread.

    ``membership_token``, if set, is the admin-signed FamilyMembership JWT
    asserting this wallet's role in the family. The wallet attaches it to
    every sign response so verifiers receive both halves of the chain in
    one round trip without coordinating with the admin out of band.

    ``callback_transport`` overrides the httpx transport used to POST async
    approval results back to a caller-supplied ``callback_url``. Tests pass
    an ``httpx.ASGITransport`` so the callback routes into a sibling ASGI
    capture app; production leaves this ``None`` for the default httpx
    transport (real TCP).
    """
    did = did_mod.did_key_from_public_key(private_key)
    approve_fn: ApproveFn = approve if approve is not None else _default_approve
    # Serialize human prompts across concurrent async approvals so two
    # callers can't interleave on stdin.
    prompt_lock = asyncio.Lock()

    app = FastAPI(title=f"household-identity wallet ({label})")

    @app.get("/")
    async def info() -> dict[str, Any]:
        return {
            "label": label,
            "did": did,
            "has_membership": membership_token is not None,
        }

    @app.post("/sign/request")
    async def sign_request(body: SignRequestBody):
        payload = vc.make_action_request(
            issuer_did=did,
            request_type=body.request_type,
            details=body.details,
            ttl_seconds=body.ttl_seconds,
        )
        message = _format_request_prompt(label, did, body.request_type, body.details)

        def sign_and_pack() -> dict[str, Any]:
            token = jws.sign_jwt(payload, key=private_key, kid=did)
            return {
                "token": token,
                "jti": payload["jti"],
                "issuer": did,
                "membership": membership_token,
            }

        if body.callback_url is None:
            return await _sync_sign(approve_fn, prompt_lock, message, sign_and_pack)
        return await _enqueue_async_approval(
            approve_fn=approve_fn,
            prompt_lock=prompt_lock,
            message=message,
            sign_and_pack=sign_and_pack,
            callback_url=body.callback_url,
            callback_transport=callback_transport,
        )

    @app.post("/sign/authorization")
    async def sign_authorization(body: SignAuthorizationBody):
        try:
            unverified = _peek_jwt(body.request_token)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"invalid request token: {e}")
        request_jti = unverified.get("jti")
        if not isinstance(request_jti, str):
            raise HTTPException(status_code=400, detail="request token missing jti")
        request_hash = vc.hash_request(body.request_token)
        message = _format_authorization_prompt(label, did, unverified, body.scope)

        def sign_and_pack() -> dict[str, Any]:
            payload = vc.make_action_authorization(
                issuer_did=did,
                request_jti=request_jti,
                request_hash=request_hash,
                scope=body.scope,
                ttl_seconds=body.ttl_seconds,
            )
            token = jws.sign_jwt(payload, key=private_key, kid=did)
            return {
                "token": token,
                "jti": payload["jti"],
                "issuer": did,
                "bound_request_jti": request_jti,
                "bound_request_hash": request_hash,
                "membership": membership_token,
            }

        if body.callback_url is None:
            return await _sync_sign(approve_fn, prompt_lock, message, sign_and_pack)
        return await _enqueue_async_approval(
            approve_fn=approve_fn,
            prompt_lock=prompt_lock,
            message=message,
            sign_and_pack=sign_and_pack,
            callback_url=body.callback_url,
            callback_transport=callback_transport,
        )

    return app


async def _sync_sign(
    approve_fn: ApproveFn,
    prompt_lock: asyncio.Lock,
    message: str,
    sign_and_pack: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    async with prompt_lock:
        approved = await approve_fn(message)
    if not approved:
        raise HTTPException(status_code=403, detail="user denied")
    return sign_and_pack()


async def _enqueue_async_approval(
    *,
    approve_fn: ApproveFn,
    prompt_lock: asyncio.Lock,
    message: str,
    sign_and_pack: Callable[[], dict[str, Any]],
    callback_url: str,
    callback_transport: httpx.AsyncBaseTransport | None,
) -> JSONResponse:
    approval_id = str(uuid.uuid4())
    asyncio.create_task(
        _run_async_approval(
            approval_id=approval_id,
            approve_fn=approve_fn,
            prompt_lock=prompt_lock,
            message=message,
            sign_and_pack=sign_and_pack,
            callback_url=callback_url,
            callback_transport=callback_transport,
        )
    )
    return JSONResponse(
        status_code=202,
        content={"approval_id": approval_id, "status": "pending"},
    )


async def _run_async_approval(
    *,
    approval_id: str,
    approve_fn: ApproveFn,
    prompt_lock: asyncio.Lock,
    message: str,
    sign_and_pack: Callable[[], dict[str, Any]],
    callback_url: str,
    callback_transport: httpx.AsyncBaseTransport | None,
) -> None:
    try:
        async with prompt_lock:
            approved = await approve_fn(message)
    except Exception as e:
        logger.exception("[wallet] approve_fn raised: %s", e)
        await _post_callback(
            callback_url,
            {"approval_id": approval_id, "status": "error", "error": str(e)},
            callback_transport,
        )
        return
    if not approved:
        await _post_callback(
            callback_url,
            {"approval_id": approval_id, "status": "denied"},
            callback_transport,
        )
        return
    bundle = sign_and_pack()
    bundle.update({"approval_id": approval_id, "status": "approved"})
    await _post_callback(callback_url, bundle, callback_transport)


async def _post_callback(
    callback_url: str,
    body: dict[str, Any],
    transport: httpx.AsyncBaseTransport | None,
) -> None:
    try:
        async with httpx.AsyncClient(timeout=10.0, transport=transport) as client:
            r = await client.post(callback_url, json=body)
        if r.status_code >= 400:
            logger.warning(
                "[wallet] callback %s returned HTTP %d: %s",
                callback_url,
                r.status_code,
                r.text[:200],
            )
    except httpx.RequestError as e:
        logger.warning("[wallet] callback %s unreachable: %s", callback_url, e)


async def _default_approve(message: str) -> bool:
    return await asyncio.to_thread(prompt_terminal, message)


def _peek_jwt(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a compact JWS")
    payload_b64 = parts[1]
    pad = "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64 + pad))


def _format_request_prompt(
    label: str, did: str, request_type: str, details: dict[str, Any]
) -> str:
    body = json.dumps(details, indent=2, sort_keys=True) if details else "{}"
    return (
        f"\nSign new ActionRequest as wallet '{label}' ({did})?\n"
        f"  type:    {request_type}\n"
        f"  details: {body}\n"
    )


def _format_authorization_prompt(
    label: str, did: str, request_payload: dict[str, Any], scope: dict[str, Any]
) -> str:
    requester = request_payload.get("iss", "<unknown>")
    req_jti = request_payload.get("jti", "<unknown>")
    requests = (
        request_payload.get("vc", {})
        .get("credentialSubject", {})
        .get("requests", {})
    )
    requests_body = json.dumps(requests, indent=2, sort_keys=True)
    scope_body = json.dumps(scope, indent=2, sort_keys=True) if scope else "{}"
    return (
        f"\nAuthorize this request as wallet '{label}' ({did})?\n"
        f"  request issuer: {requester}\n"
        f"  request jti:    {req_jti}\n"
        f"  request:        {requests_body}\n"
        f"  scope:          {scope_body}\n"
    )

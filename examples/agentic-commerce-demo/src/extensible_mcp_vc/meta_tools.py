# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Extra local tools for the proxy: request_action_vc, request_authorization_vc,
request_invoice_approval, record_fulfillment.

Each ``build_*`` function here returns a ``list[extensible_mcp.LocalTool]`` —
plain in-process tools, not a downstream MCP server — for the embedder to
pass into ``create_server(..., local_tools=[...])``. They're discovered via
``search_tools`` and invoked via ``call_tool`` exactly like a downstream
tool, so the same ``CallFilterPipeline`` (access control, the
discovered-tools guarantee, any policy filters) runs on them too — there is
no separate, unfiltered calling convention for these the way there used to
be when they were registered directly on the server.

The LLM never holds long-lived signing keys; it asks the proxy to ask the
wallets. The wallets prompt their humans and return signed VC bundles. The
LLM then passes those bundles as arguments to a gated tool, where the
governing policy verifies them against the rest of the call and the filter
strips them before the call is forwarded.

The VC tools return an *object* (not a JSON string) so the bundle shape
matches the augmented schema and the LLM can round-trip the value through
the call_tool argument unchanged.

Two wallet-call shapes are supported and selected by configuration:

- **Synchronous** (``callback_base_url`` unset) — the proxy POSTs to the
  wallet and blocks until the wallet returns the signed bundle. The wallet
  prompts on stdin and the HTTP connection stays open the whole time.
  Backwards-compatible with the v0.1 demo.
- **Asynchronous + callback** (``callback_base_url`` set) — the proxy
  generates an ``approval_id``, creates a Future, POSTs the wallet with a
  ``callback_url = {callback_base_url}/vc-callback/{approval_id}``, receives
  202 immediately, and awaits the Future. The wallet's HTTP handler returns
  right away; whenever the human approves out-of-band, the wallet POSTs the
  signed bundle to the callback URL, resolving the Future and unblocking
  the LLM-facing call. This is the path that scales to a parent who isn't
  at the terminal.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

import httpx
from extensible_mcp import LocalTool
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("extensible_mcp_vc.meta")


def register_vc_callback_route(
    server: FastMCP,
    callback_base_url: str,
    pending: dict[str, asyncio.Future],
) -> None:
    """Register the wallet-callback HTTP endpoint (if callback mode is on)
    against ``pending`` — the exact same dict the caller also passed to
    ``build_vc_tools(..., pending=...)``, so the callback and the tools
    share one pending-approvals store. The caller owns constructing
    ``pending`` (a plain ``{}``) since it's needed before ``server`` exists.

    This is a plain Starlette route, not an MCP tool — it's the wallet's
    async-approval transport, not a competing way to call a tool — so unlike
    every ``@server.tool()`` this package used to register directly, it
    still registers straight onto ``server`` rather than going through
    ``local_tools=``."""
    if callback_base_url:

        @server.custom_route("/vc-callback/{approval_id}", methods=["POST"])
        async def vc_callback(request: Request) -> Response:
            approval_id = request.path_params["approval_id"]
            try:
                body = await request.json()
            except Exception as e:
                logger.warning(
                    "[VC] callback for %r had invalid JSON body: %s",
                    approval_id,
                    e,
                )
                return JSONResponse(
                    status_code=400, content={"error": "invalid JSON"}
                )
            future = pending.pop(approval_id, None)
            if future is None or future.done():
                logger.info(
                    "[VC] callback for unknown/closed approval %r (status=%s)",
                    approval_id,
                    body.get("status"),
                )
                return JSONResponse(
                    status_code=404, content={"error": "unknown approval"}
                )
            logger.info(
                "[VC] callback resolves approval %r (status=%s)",
                approval_id,
                body.get("status"),
            )
            future.set_result(body)
            return JSONResponse({"ok": True})


def build_vc_tools(
    *,
    originator_client: httpx.AsyncClient,
    approver_client: httpx.AsyncClient,
    pending: dict[str, asyncio.Future],
    callback_base_url: str = "",
    callback_timeout_seconds: float = 150.0,
) -> list[LocalTool]:
    """Build the two VC local tools. ``pending`` must be the same dict
    :func:`register_vc_callback_route` returned, so the callback and these
    tools share one pending-approvals store."""

    async def request_action_vc_handler(arguments: dict[str, Any]) -> dict[str, Any]:
        action = arguments["action"]
        details = arguments["details"]
        logger.info(
            "[VC] request_action_vc called: action=%r details=%s",
            action,
            json.dumps(details, default=str),
        )
        if callback_base_url:
            return await _async_post_sign(
                client=originator_client,
                path="/sign/request",
                body={"request_type": action, "details": details},
                actor="originator wallet",
                pending=pending,
                callback_base_url=callback_base_url,
                callback_timeout_seconds=callback_timeout_seconds,
            )
        return await request_action_vc(originator_client, action, details)

    async def request_authorization_vc_handler(arguments: dict[str, Any]) -> dict[str, Any]:
        request = arguments["request"]
        scope = arguments.get("scope")
        logger.info(
            "[VC] request_authorization_vc called: scope=%s, request bundle "
            "received (token present: %s)",
            json.dumps(scope or {}, default=str),
            isinstance(request, dict) and isinstance(request.get("token"), str),
        )
        if callback_base_url:
            request_token, err = _extract_request_token(request)
            if err is not None:
                return err
            return await _async_post_sign(
                client=approver_client,
                path="/sign/authorization",
                body={"request_token": request_token, "scope": scope or {}},
                actor="approver wallet",
                pending=pending,
                callback_base_url=callback_base_url,
                callback_timeout_seconds=callback_timeout_seconds,
            )
        return await request_authorization_vc(approver_client, request, scope)

    return [
        LocalTool(
            name="request_action_vc",
            description=(
                "Request a signed action VC from your wallet. The wallet prompts "
                "the human at your terminal; on approval it returns an object "
                "with `token` (the signed JWS) and `membership` (the wallet's "
                "FamilyMembership VC). Pass that object as the `vc_request` "
                "argument when calling a gated tool. Returns `{\"error\": ...}` "
                "if the human declines or the wallet is unreachable."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "action": {"type": "string"},
                    "details": {"type": "object"},
                },
                "required": ["action", "details"],
            },
            handler=request_action_vc_handler,
        ),
        LocalTool(
            name="request_authorization_vc",
            description=(
                "Request a signed authorization VC from the approver's wallet, "
                "bound to a previously obtained action VC. Pass `request` as the "
                "bundle object returned by request_action_vc and an optional "
                "`scope` object. On approval, returns an object with `token` "
                "and `membership` to pass as `vc_authorization` when calling a "
                "gated tool. Returns `{\"error\": ...}` if the human declines or "
                "the wallet is unreachable."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "request": {"type": "object"},
                    "scope": {"type": "object"},
                },
                "required": ["request"],
            },
            handler=request_authorization_vc_handler,
        ),
    ]


async def request_invoice_approval(
    approval_client: httpx.AsyncClient,
    invoice: dict[str, Any],
    signature: str,
    *,
    poll_interval_seconds: float = 2.0,
    timeout_seconds: float = 300.0,
) -> dict[str, Any]:
    """The invoice-bound purchase leg's approval-collection half, standalone
    and testable — the ``LocalTool`` handler built by :func:`build_invoice_tools`
    just calls this.

    The merchant's signed invoice goes to the approval service, which (1)
    refuses it unless the merchant is in the buyer's trusted set, and (2)
    binds each human's passkey approval to the invoice hash — approving
    *these terms*, no others. Once every required role has signed, this
    returns the collected evidence for the caller to submit to a
    following, separately gated ``charge_invoice`` call — it does not
    settle anything itself (that decision belongs to the proxy's certified
    policy, not this polling loop).

    The returned ``invoice`` carries ``signature`` embedded as one of its
    own keys (not a sibling top-level field, unlike this function's own
    ``invoice``/``signature`` *parameters*) — the certified
    ``family_spend_invoice`` bundle's fetch plan has exactly one call-
    sourced credential field named ``invoice``, so the gated
    ``charge_invoice`` call needs exactly one object to pass straight
    through, signature and all, not two values to recombine."""
    logger.info(
        "[INV] request_invoice_approval: merchant=%r total=%s nonce=%s",
        invoice.get("merchantId"), invoice.get("totalCents"), invoice.get("nonce"),
    )
    try:
        r = await approval_client.post(
            "/request-invoice", json={"invoice": invoice, "signature": signature}
        )
    except httpx.RequestError as e:
        return {"error": f"could not reach the approval service: {e}"}
    if r.status_code != 200:
        return {"error": f"approval service refused the invoice: {r.text}"}
    summary = r.json()
    approval_id = summary["id"]
    required_roles = summary.get("required_roles", [])
    logger.info(
        "[INV] → pending %s; needs %s (browser passkeys), timeout %ss",
        approval_id, " + ".join(required_roles), timeout_seconds,
    )
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(poll_interval_seconds)
        try:
            p = await approval_client.get(f"/pending/{approval_id}")
        except httpx.RequestError:
            continue
        if p.status_code != 200:
            continue
        s = p.json()
        if s.get("status") in ("approved", "settled"):
            result: dict[str, Any] = {
                "status": "approved",
                "invoice": {**invoice, "signature": signature},
            }
            for role, key in (("child", "childApproval"), ("parent", "parentApproval")):
                if role not in required_roles:
                    continue
                a = await approval_client.get(f"/assertion/{approval_id}/{role}")
                if a.status_code == 200:
                    result[key] = a.json()
            logger.info(
                "[INV] ✓ approved (%s); evidence ready for charge_invoice",
                " + ".join(required_roles),
            )
            return result
    return {
        "error": (
            f"not fully approved within {timeout_seconds:.0f}s; an approver "
            "may not have the passkey page open."
        )
    }


def build_invoice_tools(
    *,
    approval_client: httpx.AsyncClient,
    poll_interval_seconds: float = 2.0,
    timeout_seconds: float = 300.0,
) -> list[LocalTool]:
    """Build ``request_invoice_approval`` (see the standalone function of
    the same name above for the actual logic) and ``record_fulfillment``."""

    async def request_invoice_approval_handler(arguments: dict[str, Any]) -> dict[str, Any]:
        return await request_invoice_approval(
            approval_client, arguments["invoice"], arguments["signature"],
            poll_interval_seconds=poll_interval_seconds,
            timeout_seconds=timeout_seconds,
        )

    async def record_fulfillment_handler(arguments: dict[str, Any]) -> dict[str, Any]:
        commitment = arguments["commitment"]
        signature = arguments["signature"]
        try:
            r = await approval_client.post(
                "/commitment", json={"commitment": commitment, "signature": signature}
            )
        except httpx.RequestError as e:
            return {"error": f"could not reach the approval service: {e}"}
        if r.status_code != 200:
            return {"error": f"commitment refused: {r.text}"}
        logger.info(
            "[INV] ✓ fulfillment commitment recorded (nonce %s)", commitment.get("nonce")
        )
        return {"ok": True, "status": "chain complete"}

    return [
        LocalTool(
            name="request_invoice_approval",
            description=(
                "Submit a merchant-signed invoice ({invoice, signature} from "
                "request_invoice) for human passkey approval. Waits for every "
                "required role (child always; parent too, above the $10 solo "
                "threshold) to approve with a biometric bound to these exact "
                "invoice terms, then returns the collected evidence "
                "{invoice (with the merchant's signature embedded — pass it "
                "straight through, do not split it apart), childApproval, "
                "parentApproval?} — pass this straight through as arguments to "
                "the settlement server's gated `charge_invoice` tool (via "
                "call_tool, alongside the same amountCents/merchantId you "
                "already used) to actually charge the rail; this tool only "
                "collects approvals, it does not charge anything itself. "
                "Returns `{\"error\": ...}` if the "
                "merchant is untrusted, an approver declines, or the wait "
                "times out."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "invoice": {"type": "object"},
                    "signature": {"type": "string"},
                },
                "required": ["invoice", "signature"],
            },
            handler=request_invoice_approval_handler,
        ),
        LocalTool(
            name="record_fulfillment",
            description=(
                "File the merchant's signed fulfillment commitment "
                "({commitment, signature} from the merchant's fulfill tool) into "
                "the family's evidence chain. Call this after a successful "
                "fulfill — it completes the audit trail (terms → consent → "
                "payment → obligation). The service verifies the merchant "
                "signature and matches the commitment to the settled invoice."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "commitment": {"type": "object"},
                    "signature": {"type": "string"},
                },
                "required": ["commitment", "signature"],
            },
            handler=record_fulfillment_handler,
        ),
    ]


# ---------------------------------------------------------------------------
# Synchronous helpers (also used directly in tests)
# ---------------------------------------------------------------------------


async def request_action_vc(
    client: httpx.AsyncClient, action: str, details: dict[str, Any]
) -> dict[str, Any]:
    return await _post_sign(
        client,
        "/sign/request",
        {"request_type": action, "details": details},
        actor="originator wallet",
    )


async def request_authorization_vc(
    client: httpx.AsyncClient,
    request: dict[str, Any],
    scope: dict[str, Any] | None,
) -> dict[str, Any]:
    request_token, err = _extract_request_token(request)
    if err is not None:
        return err
    return await _post_sign(
        client,
        "/sign/authorization",
        {"request_token": request_token, "scope": scope or {}},
        actor="approver wallet",
    )


async def _post_sign(
    client: httpx.AsyncClient,
    path: str,
    body: dict[str, Any],
    *,
    actor: str,
) -> dict[str, Any]:
    logger.info("[VC] → POST %s to %s for human approval", path, actor)
    try:
        r = await client.post(path, json=body)
    except httpx.RequestError as e:
        logger.warning("[VC] ✗ could not reach %s: %s", actor, e)
        return {"error": f"could not reach {actor}: {e}"}
    if r.status_code == 403:
        logger.warning("[VC] ✗ human declined at %s", actor)
        return {"error": f"human declined the request at the {actor}."}
    if r.status_code != 200:
        logger.warning(
            "[VC] ✗ %s returned HTTP %d: %s", actor, r.status_code, r.text
        )
        return {"error": f"{actor} returned HTTP {r.status_code}: {r.text}"}
    body_out = r.json()
    logger.info(
        "[VC] ✓ %s returned signed bundle (membership attached: %s)",
        actor,
        body_out.get("membership") is not None,
    )
    return {
        "token": body_out["token"],
        "membership": body_out.get("membership"),
    }


# ---------------------------------------------------------------------------
# Asynchronous helper (callback-driven)
# ---------------------------------------------------------------------------


async def _async_post_sign(
    *,
    client: httpx.AsyncClient,
    path: str,
    body: dict[str, Any],
    actor: str,
    pending: dict[str, asyncio.Future],
    callback_base_url: str,
    callback_timeout_seconds: float,
) -> dict[str, Any]:
    approval_id = str(uuid.uuid4())
    callback_url = f"{callback_base_url.rstrip('/')}/vc-callback/{approval_id}"
    future: asyncio.Future = asyncio.get_running_loop().create_future()
    pending[approval_id] = future
    posted_body = dict(body)
    posted_body["callback_url"] = callback_url
    logger.info(
        "[VC] → POST %s to %s for human approval (async, approval_id=%s, "
        "callback=%s, timeout=%ss)",
        path,
        actor,
        approval_id,
        callback_url,
        callback_timeout_seconds,
    )
    try:
        r = await client.post(path, json=posted_body)
    except httpx.RequestError as e:
        pending.pop(approval_id, None)
        logger.warning("[VC] ✗ could not reach %s: %s", actor, e)
        return {"error": f"could not reach {actor}: {e}"}
    if r.status_code not in (200, 202):
        pending.pop(approval_id, None)
        logger.warning(
            "[VC] ✗ %s returned HTTP %d on async POST: %s",
            actor,
            r.status_code,
            r.text,
        )
        return {"error": f"{actor} returned HTTP {r.status_code}: {r.text}"}
    if r.status_code == 200:
        # Wallet doesn't support async; treat as synchronous reply.
        pending.pop(approval_id, None)
        body_out = r.json()
        logger.info(
            "[VC] ✓ %s answered synchronously despite async POST", actor
        )
        return {
            "token": body_out["token"],
            "membership": body_out.get("membership"),
        }
    # 202 — wait on the callback to land.
    try:
        result = await asyncio.wait_for(future, timeout=callback_timeout_seconds)
    except asyncio.TimeoutError:
        pending.pop(approval_id, None)
        logger.warning(
            "[VC] ✗ %s did not respond within %ss for approval %s",
            actor,
            callback_timeout_seconds,
            approval_id,
        )
        return {
            "error": (
                f"{actor} did not respond within "
                f"{callback_timeout_seconds:.0f}s; the human may not be at "
                f"the wallet."
            )
        }
    status = result.get("status")
    if status == "denied":
        logger.warning("[VC] ✗ human declined at %s (approval %s)", actor, approval_id)
        return {"error": f"human declined the request at the {actor}."}
    if status == "error":
        logger.warning(
            "[VC] ✗ %s reported error for approval %s: %s",
            actor,
            approval_id,
            result.get("error"),
        )
        return {"error": f"{actor} error: {result.get('error')}"}
    if "token" not in result:
        logger.warning(
            "[VC] ✗ %s callback for %s missing token field: %s",
            actor,
            approval_id,
            result,
        )
        return {"error": f"{actor} callback missing token field"}
    logger.info(
        "[VC] ✓ %s callback delivered signed bundle (approval %s, membership "
        "attached: %s)",
        actor,
        approval_id,
        result.get("membership") is not None,
    )
    return {
        "token": result["token"],
        "membership": result.get("membership"),
    }


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _extract_request_token(
    request: Any,
) -> tuple[str | None, dict[str, Any] | None]:
    """Return (request_token, None) on success or (None, error_dict)."""
    if isinstance(request, str):
        try:
            request = json.loads(request)
        except (ValueError, TypeError):
            return None, {
                "error": "`request` must be the bundle returned by request_action_vc (object, or its JSON string form)."
            }
    if not isinstance(request, dict):
        return None, {
            "error": "`request` must be the bundle object returned by request_action_vc."
        }
    request_token = request.get("token")
    if not isinstance(request_token, str):
        return None, {
            "error": (
                "`request` is missing a string `token` field; pass the bundle "
                "object returned by request_action_vc."
            )
        }
    return request_token, None

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""HTTP proxy with a supplied policy bundle as the live authority AND the real wallets.

Unlike ``boot_demo.py`` (same bundle authority, but keys minted in-process
and calls scripted rather than driven by a human), this wires the
**policy-bundle enforcement path** — ``BundleRouter`` + ``VCPolicyFilter`` over
``family_spend_prod`` — together with the **real wallet meta-tools**, so a run
drives the actual kid/parent shells. It is the "run against the existing
infrastructure" server.

Reads wallet URLs, the trusted admin set, and the admin's DID document from a
workspace ``vc-config.json`` (as written by ``setup.py``). The downstream
``payments`` server is the merchant-speaking ``demo_spend_server`` (the policy
binds ``merchant``).

Manifest validation is on by default: the manifest's wallet-supplied claim
bodies are open (``additionalProperties: true``) so real wallets' open-world
``@context``/``type``/``jti``/… extras validate cleanly alongside the fields
the policy actually reads.

The policy requester role is aligned to the wallets' ``"child"``, so the
``drive_demo.py`` scenario runs green: a $15 request is
over the $10 solo tier, so it is denied with only the kid's request VC and
allowed once the parent authorizes it (both shells exercised).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from mcp.client.stdio import get_default_environment

from extensible_mcp import (
    BundleRouter,
    DidWebResolver,
    LayeredBundleSelector,
    PolicyBundle,
    SingleUseEvidenceFilter,
    VCPolicyFilter,
    WalletBundleAdapter,
    ed25519_jwk_from_document,
)
from extensible_mcp.filters import AccessControlFilter
from extensible_mcp.augment import BundleAugmenter
from extensible_mcp.config import Config
from extensible_mcp.server import create_server
from extensible_mcp.types import CallFilterResult, CallRequest, ServerConfig
from extensible_mcp.wasm_filter import WasmPolicyFilter
from extensible_mcp.wasm_policy import default_builtins
from extensible_mcp_vc.invoice import canonical_invoice
from extensible_mcp_vc.meta_tools import (
    build_invoice_tools,
    build_vc_tools,
    register_vc_callback_route,
)

_FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures"
BUNDLE_DIR = _FIXTURES / "family_spend_prod"
# The Rego bundle, certified by the external
# policy-authoring toolchain. A CEL twin exists
# (tests/fixtures/cel_family_spend_invoice) and is proven equivalent by
# tests/test_invoice_policy.py, but only the Rego bundle is wired into this
# live demo — matching how the other two rails have only ever run Rego here
# too; CEL has so far only ever been proven via tests, not live traffic.
INVOICE_BUNDLE_DIR = _FIXTURES / "family_spend_invoice"
PROJECT = Path(__file__).resolve().parent.parent

# The WebAuthn approval surface (approval_service.py). Its URL fixes both
# policy inputs: webauthnOrigin (checked in-policy) and the rpId baked into
# the verify_webauthn builtin.
APPROVAL_URL = os.environ.get("APPROVAL_URL", "http://localhost:7500")

# Downstream execution rail, chosen by the DOWNSTREAM env var:
#   DOWNSTREAM=demo    (default) mock in-memory balance — demo_spend_server.py
#   DOWNSTREAM=stripe  real test-mode card charge — stripe_spend_server.py
#                      (needs `uv sync --extra stripe` + STRIPE_API_KEY=sk_test_…)
# Any other value is treated as a path to a downstream server script.
_DOWNSTREAMS = {"demo": "demo_spend_server.py", "stripe": "stripe_spend_server.py"}
_choice = os.environ.get("DOWNSTREAM", "demo")
DOWNSTREAM = Path(__file__).resolve().parent / _DOWNSTREAMS.get(_choice, _choice)
PIZZA_SERVER = Path(__file__).resolve().parent / "pizza_server.py"
SETTLEMENT_SERVER = Path(__file__).resolve().parent / "settlement_server.py"

# The demo governs specific actions, not whole servers: informational tools
# on the same downstream (list_stores, get_menu, balance) stay credential-free.
GATED_ACTIONS = {"spend", "order_pizza", "charge_invoice"}
_CREDENTIAL_FIELDS = ("requestVC", "authorizationVC", "invoice", "childApproval", "parentApproval")

# `spend` and `order_pizza` are gated by the wallet-VC rail (request_action_vc
# posts to the kid/parent wallet *web pages* for human approval). In a
# deployment that doesn't publish those pages — the containerized demo,
# deliberately down to 3 exposed surfaces — a request through either tool
# has nowhere to be approved: it just sits there, indistinguishable from a
# hang. Rather than tell the LLM not to call them (a suggestion, not a
# guarantee — it already picked order_pizza once anyway), hide them from
# search_tools structurally: DiscoveredToolsFilter already enforces that the
# LLM can only call what search surfaced, so an unsurfaced tool is
# uncallable, not just discouraged. Set by the container's entrypoint; unset
# (default) for the manual walkthrough in examples/README.md, where the
# wallet pages really are reachable.
HIDE_WALLET_GATED_TOOLS = os.environ.get("HIDE_WALLET_GATED_TOOLS", "false").lower() == "true"


def _action(tool_name: str) -> str:
    return tool_name.split("__", 1)[1] if "__" in tool_name else tool_name


class ToolScopedFilter:
    """Apply the bundle filter only to the gated actions; other tools on the
    governed server pass through (with any stray credential args stripped, so
    the downstream never sees arguments its schema does not declare)."""

    def __init__(self, inner: VCPolicyFilter) -> None:
        self._inner = inner

    @property
    def bundle(self):  # the augmenter reads router.bundle_for() -> filter.bundle
        return self._inner.bundle

    async def check(self, request: CallRequest) -> CallFilterResult:
        if _action(request.tool_name) not in GATED_ACTIONS:
            args = {
                k: v for k, v in request.arguments.items()
                if k not in _CREDENTIAL_FIELDS
            }
            return CallFilterResult(
                allowed=True, tool_name=request.tool_name, arguments=args
            )
        return await self._inner.check(request)


class PizzaWireAdapter(WalletBundleAdapter):
    """``order_pizza`` speaks ``(store, total)``; the policy binds
    ``(merchant, amountCents)``. Rename for the policy view only — the
    downstream still receives the original ``store``/``total`` arguments
    (the filter forwards the original request's args, not the adapter's).

    The projection applies on **both** sides of the binding: the call
    arguments and the *signed request's* decoded view. Value-preserving
    aliasing of signed content is the same class of transform as the cents
    seam — the signature still covers the original bytes; the policy just
    reads the wallet's vocabulary under its own field names."""

    def adapt(self, request: CallRequest):
        args = dict(request.arguments)
        if "total" in args:
            args["amount"] = args.pop("total")
        if "store" in args:
            args["merchant"] = args.pop("store")
        return super().adapt(
            CallRequest(
                tool_name=request.tool_name,
                arguments=args,
                server_name=request.server_name,
                session_id=request.session_id,
            )
        )

    def _to_vc(self, bundle, *, normalize_request: bool):
        vc = super()._to_vc(bundle, normalize_request=normalize_request)
        if normalize_request:
            requests = (
                vc["claims"].get("vc", {}).get("credentialSubject", {}).get("requests")
            )
            if isinstance(requests, dict):
                if "merchant" not in requests and isinstance(requests.get("store"), str):
                    requests["merchant"] = requests["store"]
                if "amountCents" not in requests and isinstance(
                    requests.get("total"), (int, float)
                ):
                    requests["amountCents"] = int(
                        (Decimal(str(requests["total"])) * 100).to_integral_value(
                            ROUND_HALF_UP
                        )
                    )
        return vc


class InvoiceGatedFilter:
    """The invoice-settlement rail's wire adapter —
    not a ``WalletBundleAdapter`` subclass like the other two rails, since
    there is no wallet-issued VC anywhere in this flow.

    ``request_invoice_approval`` hands the LLM a single ``invoice`` object
    with the merchant's signature embedded as one of its own keys (see its
    own docstring for why) — matching ``family_spend_invoice``'s fetch plan,
    which has exactly one call-sourced credential field named ``invoice``.
    This adapter's only job is reshaping that one field into what the
    certified bundle actually expects: ``{canonical, signature}``, where
    ``canonical`` is computed here from the invoice's own fields, never
    retyped by the LLM (the wire-form principle — hash/sign the
    wire form, never re-canonicalize elsewhere and hope it matches).

    Everything else — ``amountCents``/``merchantId`` (the call's own native
    claims, bound against the signed invoice by the policy), ``childApproval``,
    and ``parentApproval`` (already in the exact WebAuthn-assertion shape
    the bundle expects) — passes through unchanged.

    ``trustedMerchants`` is fetched fresh on every call, not baked into a
    static ``config`` dict at construction time: trust here is established
    dynamically (this demo's own boot-time trust exchange, or a later
    addition), and ``WasmPolicyFilter``'s ``config`` is a one-time snapshot
    — a merchant trusted after the proxy started would otherwise be denied
    forever without a proxy restart. A fresh ``WasmPolicyFilter`` is
    constructed per call with the current set; this is cheap (it just wraps
    the same already-loaded bundle/policy object with fresh config, no
    wasm re-instantiation)."""

    def __init__(
        self,
        bundle: PolicyBundle,
        *,
        base_config: dict[str, Any],
        wallet_lookup,
        trusted_merchants_client: httpx.AsyncClient,
    ) -> None:
        self._bundle = bundle
        self._base_config = dict(base_config)
        self._wallet_lookup = wallet_lookup
        self._trusted_merchants_client = trusted_merchants_client

    @property
    def bundle(self):
        return self._bundle

    async def _fetch_trusted_merchants(self) -> list[dict[str, str]]:
        try:
            r = await self._trusted_merchants_client.get("/trusted-merchants")
        except httpx.RequestError:
            return []
        if r.status_code != 200:
            return []
        return r.json()

    async def check(self, request: CallRequest) -> CallFilterResult:
        invoice_wire = request.arguments.get("invoice")
        if not isinstance(invoice_wire, dict) or not isinstance(
            invoice_wire.get("signature"), str
        ):
            downstream_args = {
                k: v for k, v in request.arguments.items()
                if k not in ("invoice", "childApproval", "parentApproval")
            }
            return CallFilterResult(
                allowed=False,
                reason=(
                    "invoice must be an object carrying the merchant's "
                    "signature (as request_invoice_approval returns it)"
                ),
                tool_name=request.tool_name,
                arguments=downstream_args,
            )
        signature = invoice_wire["signature"]
        invoice_fields = {k: v for k, v in invoice_wire.items() if k != "signature"}
        # `nonce` names which approved invoice the settlement service should
        # charge. The certified bundle's InvoiceArgs contract is closed and
        # does not include it, and it is not a claim the policy needs: the
        # approval challenge already binds the whole canonical invoice, nonce
        # included. So bind it here instead -- it must be *this* invoice's
        # nonce -- then keep it out of the policy's view of `arguments` and
        # put it back on the downstream call.
        nonce = request.arguments.get("nonce")
        if nonce is not None and nonce != invoice_fields.get("nonce"):
            return CallFilterResult(
                allowed=False,
                reason=(
                    "nonce does not match the invoice's own nonce — pass the "
                    "nonce of the invoice you had approved, so settlement "
                    "charges that invoice and no other"
                ),
                tool_name=request.tool_name,
                arguments={
                    k: v for k, v in request.arguments.items()
                    if k not in ("invoice", "childApproval", "parentApproval")
                },
            )
        # canonical_invoice(), not a re-typed copy of its serialization
        # parameters — the exact same function the merchant's own signature
        # (invoice.py: sign_invoice) and the approval service's own
        # verification (verify_invoice) both use, so this is guaranteed
        # byte-for-byte identical to what was actually signed.
        canonical = canonical_invoice(invoice_fields).decode()
        adapted_args = dict(request.arguments)
        adapted_args.pop("nonce", None)
        adapted_args["invoice"] = {"canonical": canonical, "signature": signature}
        adapted = CallRequest(
            tool_name=request.tool_name,
            arguments=adapted_args,
            server_name=request.server_name,
            session_id=request.session_id,
        )
        inner = WasmPolicyFilter(
            self._bundle,
            config={
                **self._base_config,
                "trustedMerchants": await self._fetch_trusted_merchants(),
            },
            wallet_lookup=self._wallet_lookup,
            # See the class docstring's manifest note: this
            # bundle's manifest has no `tool` property and is
            # additionalProperties:false at the root, but
            # WasmPolicyFilter.check() always sets envelope["tool"] — so
            # validation would fail on every allowed call, not just
            # malformed ones. The invoice-hash challenge already binds the
            # approval to this exact invoice, a stronger binding than a
            # canonicalized tool name would add, so skipping validation
            # here costs nothing this bundle was actually relying on.
            validate_input=False,
        )
        result = await inner.check(adapted)
        if nonce is not None:
            result.arguments = {**result.arguments, "nonce": nonce}
        return result


class ToolScopedAugmenter:
    """Augment only the gated tools' definitions — an ungated tool on a
    governed server must not advertise credential parameters."""

    def __init__(self, inner: BundleAugmenter) -> None:
        self._inner = inner

    def filter(self, results, query):
        out = []
        for r in results:
            if _action(r.tool.qualified_name) in GATED_ACTIONS:
                out.extend(self._inner.filter([r], query))
            else:
                out.append(r)
        return out


def build_bundle_router(
    *,
    trusted: list[str],
    preresolved: dict[str, Any],
    approval_client: httpx.AsyncClient,
) -> tuple[BundleRouter, DidWebResolver]:
    """Assemble the server -> bundle -> filter wiring this demo runs on.

    A module-level function rather than inline in ``main()`` so a test can
    build the real thing -- the same literal map, the same adapters, the same
    replay guard -- instead of a copy that passes while the live wiring
    drifts. Returns the resolver too, since callers need it to mint evidence
    the same admin key vouches for.
    """
    bundle = PolicyBundle.load(BUNDLE_DIR, name="family_spend_prod")
    resolver = DidWebResolver(trusted, preresolved=preresolved)

    # -- the invoice rail: bundle, origin/rpId, enrollment lookup ----------- #
    approval_origin = urlparse(APPROVAL_URL)
    invoice_bundle = PolicyBundle.load(
        INVOICE_BUNDLE_DIR,
        name="family_spend_invoice",
        builtins=default_builtins(webauthn_rp_id=approval_origin.hostname),
    )
    approval_http = approval_client

    async def enrollment_lookup(subject: str):
        """approverEnrollment by credentialId: the admin-signed enrollment VC
        from the approval service, adminKey attached like a membership."""
        try:
            r = await approval_http.get(f"/enrollment/{subject}")
        except httpx.RequestError:
            return None
        if r.status_code != 200:
            return None
        return await resolver.attach_admin_key(r.json())

    def filter_factory(name: str):
        # Four routes, three bundles: pizza and payments-VC share the prod
        # policy with different wire adapters; settlement runs the
        # certified invoice bundle (no wallet VC at all — see
        # InvoiceGatedFilter).
        if name == "family_spend_invoice":
            return ToolScopedFilter(
                InvoiceGatedFilter(
                    invoice_bundle,
                    base_config={
                        "webauthnOrigin":
                            f"{approval_origin.scheme}://{approval_origin.netloc}",
                        "trustedAdminDids": trusted,
                        # trustedMerchants deliberately absent here — fetched
                        # fresh per call (see InvoiceGatedFilter), not baked
                        # in as a static snapshot.
                    },
                    wallet_lookup=enrollment_lookup,
                    trusted_merchants_client=approval_http,
                )
            )
        adapters = {
            "family_spend_pizza": PizzaWireAdapter(),
            # payments__spend speaks the policy's own vocabulary already, so
            # the base adapter (dollars -> amountCents, membership harvest)
            # is all it needs.
            "family_spend_prod": WalletBundleAdapter(),
        }
        adapter = adapters.get(name)
        if adapter is None:
            return None
        return ToolScopedFilter(
            # Single-use, because the policy cannot be: it is a pure function
            # of the evidence and the call, so the same VC pair re-sent with
            # the same arguments decides the same way and the spend happens
            # again. Keyed on the request VC's jti, which is inside what the
            # kid signed. Wrapping rather than appending is deliberate --
            # VCPolicyFilter strips the credentials from the arguments it
            # passes on, and a guard must spend the evidence only when the
            # policy actually allowed the call.
            SingleUseEvidenceFilter(
                VCPolicyFilter(
                    bundle,
                    adapter=adapter,  # LLM passes requestVC / authorizationVC
                    resolver=resolver,
                    trusted_admin_dids=trusted,
                    # validate_input defaults on — re-pinned 2026-09-09 to the
                    # manifest (wallet-supplied claim bodies open).
                ),
                credential_fields=(adapter.request_field,),
            )
        )

    selector = LayeredBundleSelector(
        literal_map={
            "payments": "family_spend_prod",
            "pizza": "family_spend_pizza",
            "settlement": "family_spend_invoice",
        },
        map_key="origin_server",
    )
    router = BundleRouter(selector, filter_factory)

    return router, resolver


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(prog="family_proxy_server")
    parser.add_argument(
        "--vc-config", type=Path,
        default=PROJECT / "workspace" / "vc-config.json",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7400)
    args = parser.parse_args()

    vc = json.loads(args.vc_config.read_text())
    trusted = vc["trusted_admin_dids"]

    preresolved = {}
    for did, doc in vc.get("preresolved_did_documents", {}).items():
        jwk = ed25519_jwk_from_document(doc)
        if jwk is not None:
            preresolved[did] = jwk

    approval_http = httpx.AsyncClient(base_url=APPROVAL_URL, timeout=310.0)
    router, resolver = build_bundle_router(
        trusted=trusted,
        preresolved=preresolved,
        approval_client=approval_http,
    )

    # The MCP stdio transport sanitizes the child's environment to a small
    # whitelist (PATH, HOME, …), which drops STRIPE_API_KEY. Pass the Stripe
    # vars through explicitly so the downstream charge server sees the key.
    downstream_env = {
        **get_default_environment(),
        **{k: v for k, v in os.environ.items() if k.startswith("STRIPE_")},
    }

    # PIZZA_URL points at a remote pizza parlor (its own container/service,
    # Streamable HTTP); unset, the parlor runs as a local stdio child.
    pizza_url = os.environ.get("PIZZA_URL")
    pizza_server_config = (
        ServerConfig(name="pizza", url=pizza_url)
        if pizza_url
        else ServerConfig(
            name="pizza",
            command="uv",
            args=["run", "--project", str(PROJECT), "python", str(PIZZA_SERVER)],
            env={
                **downstream_env,
                "PIZZA_ORDERS_LOG": str(PROJECT / "workspace" / "pizza-orders.log"),
            },
        )
    )
    config = Config(
        servers=[
            ServerConfig(
                name="payments",
                command="uv",
                args=["run", "--project", str(PROJECT), "python", str(DOWNSTREAM)],
                env=downstream_env,
            ),
            pizza_server_config,
            ServerConfig(
                name="settlement",
                command="uv",
                args=["run", "--project", str(PROJECT), "python", str(SETTLEMENT_SERVER)],
                env={**downstream_env, "APPROVAL_URL": APPROVAL_URL},
            ),
        ]
    )
    # What the LLM actually sends on the wire is the wallet bundle — the
    # adapter turns it into the manifest's {jws, claims} shape. Advertise the
    # wire shape, or the LLM "fixes" a working call to match the policy shape.
    wire_vc = {
        "type": "object",
        "required": ["token"],
        "properties": {
            "token": {
                "type": "string",
                "description": "The compact JWS from the wallet, passed verbatim.",
            },
            "membership": {
                "type": "string",
                "description": "The membership JWS the wallet attached, passed verbatim.",
            },
        },
    }
    wire_approval = {
        "type": "object",
        "required": ["credentialId", "authenticatorData", "clientDataJSON", "signature"],
        "properties": {
            k: {"type": "string"}
            for k in ("credentialId", "authenticatorData", "clientDataJSON", "signature")
        },
        "description": (
            "A passkey assertion object, exactly as the approval service "
            "returned it — pass it verbatim."
        ),
    }
    wire_invoice = {
        "type": "object",
        "required": ["signature"],
        "properties": {
            "signature": {
                "type": "string",
                "description": "The merchant's signature over this invoice's own fields.",
            },
        },
        "description": (
            "The `invoice` object exactly as request_invoice_approval returned "
            "it — its own fields plus `signature` embedded — pass it verbatim, "
            "do not split it apart or retype any of its fields."
        ),
    }
    augmenter = BundleAugmenter(
        router,
        wire_schemas={
            "requestVC": wire_vc,
            "authorizationVC": wire_vc,
            "invoice": wire_invoice,
            "childApproval": wire_approval,
            "parentApproval": wire_approval,
        },
    )
    search_filters: list = []
    if HIDE_WALLET_GATED_TOOLS:
        search_filters.append(
            AccessControlFilter(deny=["payments__spend", "pizza__order_pizza"])
        )
    search_filters.append(ToolScopedAugmenter(augmenter))

    originator = httpx.AsyncClient(base_url=vc["originator_wallet_url"], timeout=300.0)
    approver = httpx.AsyncClient(base_url=vc["approver_wallet_url"], timeout=300.0)
    # The VC callback route (registered below, after create_server) needs a
    # live server to register on, but the tools it shares a `pending` store
    # with need to exist before create_server owns building the FastMCP
    # object — so `pending` is built here, first, and threaded to both.
    pending: dict = {}
    local_tools = [
        *build_vc_tools(originator_client=originator, approver_client=approver, pending=pending),
        *build_invoice_tools(approval_client=approval_http),
    ]

    server = create_server(
        config,
        bundle_router=router,
        extra_search_filters=search_filters,
        local_tools=local_tools,
    )
    register_vc_callback_route(server, callback_base_url="", pending=pending)

    print(f"family-authority proxy on http://{args.host}:{args.port}/mcp/  "
          f"(downstreams: {DOWNSTREAM.name} + {PIZZA_SERVER.name} + "
          f"{SETTLEMENT_SERVER.name}; "
          f"gated: {sorted(GATED_ACTIONS)}; "
          f"rails: spend + order_pizza=VC wallets "
          f"({vc['originator_wallet_url']} , {vc['approver_wallet_url']}) , "
          f"charge_invoice=certified policy ({INVOICE_BUNDLE_DIR.name})")
    server.run(transport="http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()

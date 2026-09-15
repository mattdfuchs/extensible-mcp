# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests for per-server bundle routing: admission at load and dispatch at call,
wiring stage-one selection to call-path enforcement."""

from __future__ import annotations

from pathlib import Path

import pytest

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.routing import BundleRouter
from extensible_mcp.selection import LayeredBundleSelector, RegoClassifier
from extensible_mcp.server import _admit_servers
from extensible_mcp.types import CallRequest, ServerConfig
from extensible_mcp.wasm_filter import WasmPolicyFilter
from tests import vc_helpers as vc

FIXTURES = Path(__file__).parent / "fixtures"
CLASSIFIER_WASM = FIXTURES / "classifier" / "policy.wasm"
FAMILY_SPEND_DIR = FIXTURES / "family_spend"


@pytest.fixture(scope="module")
def key():
    return vc.new_key()


def _family_spend_filter(key) -> WasmPolicyFilter:
    bundle = PolicyBundle.load(FAMILY_SPEND_DIR, name="family_spend")
    table = {
        vc.KID_DID: vc.membership(sub=vc.KID_DID, role="kid", key=key),
        vc.PARENT_DID: vc.membership(sub=vc.PARENT_DID, role="parent", key=key),
    }

    async def wallet_lookup(subject: str):
        return table.get(subject)

    return WasmPolicyFilter(
        bundle,
        config={"trustRootDID": vc.TRUST_DID, "trustRootJwk": vc.public_jwk(key)},
        wallet_lookup=wallet_lookup,
        clock=lambda: 100,
    )


def _router(key, literal_map=None) -> BundleRouter:
    selector = LayeredBundleSelector(literal_map, RegoClassifier(CLASSIFIER_WASM))

    def factory(bundle_name: str):
        # The deployment only provides the family_spend bundle here.
        return _family_spend_filter(key) if bundle_name == "family_spend" else None

    return BundleRouter(selector, factory)


def _send_call(key, *, amount=500, server="payments", tool=None) -> CallRequest:
    args = {"amountCents": amount, "merchant": "acme"}
    req = vc.request_vc(args=args, key=key)
    arguments = {
        **args,
        "requestVC": req,
        "authorizationVC": {
            "jws": req["jws"],
            "claims": {"jti": "r1", "iss": vc.PARENT_DID, "requestHash": "0" * 64,
                       "nbf": 0, "exp": 9999999999},
        },
    }
    return CallRequest(
        tool_name=tool or f"{server}__send", arguments=arguments, server_name=server
    )


# -- admission --------------------------------------------------------------- #


def test_admits_payments_to_family_spend(key):
    router = _router(key)
    result = router.admit(server_name="payments", url="https://p.example", how_loaded="static")
    assert result.allowed and result.bundle == "family_spend"
    assert router.governs("payments")


def test_refuses_unclassified_server(key):
    router = _router(key)
    result = router.admit(server_name="weather", url="https://w.example", how_loaded="static")
    assert not result.allowed and not router.governs("weather")


def test_unavailable_bundle_fails_closed(key):
    # classifier routes a sandbox server to "readonly", which the factory
    # does not provide → refused.
    router = _router(key)
    result = router.admit(
        server_name="other", url="https://o.example", how_loaded="static",
        trust_tier="sandbox",
    )
    assert not result.allowed
    assert "unavailable" in result.reason and not router.governs("other")


def test_map_ban_refuses_at_admission(key):
    router = _router(key, {"https://p.example": "banned"})
    result = router.admit(server_name="payments", url="https://p.example", how_loaded="static")
    assert not result.allowed and not router.governs("payments")


# -- routing (BundleRouter is a CallFilter) ---------------------------------- #


async def test_routes_governed_call_to_bundle_filter(key):
    router = _router(key)
    router.admit(server_name="payments", url="https://p.example", how_loaded="static")
    result = await router.check(_send_call(key))
    assert result.allowed
    # credential args stripped by the bundle filter
    assert result.arguments == {"amountCents": 500, "merchant": "acme"}


async def test_routes_governed_call_denies_on_tamper(key):
    router = _router(key)
    router.admit(server_name="payments", url="https://p.example", how_loaded="static")
    call = _send_call(key)
    jws = call.arguments["requestVC"]["jws"]
    call.arguments["requestVC"]["jws"] = jws[:-6] + ("A" if jws[-1] != "A" else "B") * 6
    result = await router.check(call)
    assert not result.allowed


async def test_ungoverned_server_passes_through(key):
    router = _router(key)
    # never admitted "weather" → not governed → pass through unchanged
    call = _send_call(key, server="weather", tool="weather__forecast")
    result = await router.check(call)
    assert result.allowed
    assert result.arguments == call.arguments  # untouched, including VC fields


# -- load-time admission helper --------------------------------------------- #


def test_admit_servers_filters_refused(key):
    router = _router(key)
    servers = [
        ServerConfig(name="payments", url="https://payments.example"),
        ServerConfig(name="weather", url="https://weather.example"),
    ]
    admitted = _admit_servers(router, servers)
    names = {s.name for s in admitted}
    assert names == {"payments"}  # weather refused (classifier → deny_all)

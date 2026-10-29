# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The ``caller`` fetch-plan source: a policy reads who the session acts for
the way it reads the clock -- from the proxy, never from the call."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.config import load_config
from extensible_mcp.fetchplan import DerivePlanError, FetchContext, FetchError, FetchExecutor
from extensible_mcp.server import create_server
from extensible_mcp.types import CallRequest, Principal
from extensible_mcp.wasm_filter import WasmPolicyFilter
from tests import vc_helpers as vc

FIXTURES = Path(__file__).parent / "fixtures"
MINIMAL_SPEND = FIXTURES / "minimal_spend"
PAYMENTS_SERVER = str(Path(__file__).parent / "mock_payments_server.py")

PARENT = Principal(
    sub="parent-1", iss="https://idp.example", roles=frozenset({"parent", "admin"}),
    client_id="console", amr=("webauthn",),
)


@pytest.fixture(scope="module")
def key():
    return vc.new_key()


def _with_caller(*fields: str):
    """Add one ``caller`` entry per field, as ``caller<Field>``, and declare
    each in the closed manifest so the assembled input still validates."""
    names = {f: "caller" + f[0].upper() + f[1:].replace("_", "") for f in fields}

    def plan(doc):
        for f, name in names.items():
            doc["entries"].append({
                "field": name,
                "source": {"kind": "caller", "params": {"field": f}},
                "schema": {},
            })

    def manifest(doc):
        for name in names.values():
            doc["properties"][name] = {}
            doc["required"].append(name)

    return plan, manifest


def _ctx(key, principal) -> FetchContext:
    args = {"amountCents": 500, "merchant": "acme"}
    return FetchContext(
        envelope={"tool": "send", "arguments": args, "requestVC": vc.request_vc(args=args, key=key)},
        config={"requesterJwk": vc.public_jwk(key)},
        now=100,
        principal=principal,
    )


async def test_the_callers_facts_are_assembled_from_the_principal(rewritten_bundle, key):
    plan, manifest = _with_caller("sub", "roles", "amr", "client_id")
    bundle = PolicyBundle.load(rewritten_bundle(MINIMAL_SPEND, plan=plan, manifest=manifest))
    assembled = await FetchExecutor().assemble(bundle.fetchplan, _ctx(key, PARENT))
    assert assembled["callerSub"] == "parent-1"
    assert assembled["callerRoles"] == ["admin", "parent"]  # sorted: the input stays JSON
    assert assembled["callerAmr"] == ["webauthn"]
    assert assembled["callerClientid"] == "console"
    assert bundle.validate_input(assembled) == []
    # Not a credential: nothing is advertised to the model, nothing stripped.
    assert bundle.credential_fields() == ["requestVC"]


async def test_no_principal_fails_closed_as_a_denial_not_a_fault(rewritten_bundle, key):
    plan, manifest = _with_caller("sub")
    bundle = PolicyBundle.load(rewritten_bundle(MINIMAL_SPEND, plan=plan, manifest=manifest))
    with pytest.raises(FetchError, match="no authenticated principal"):
        await FetchExecutor().assemble(bundle.fetchplan, _ctx(key, None))

    args = {"amountCents": 500, "merchant": "acme"}
    policy = WasmPolicyFilter(bundle, config={"requesterJwk": vc.public_jwk(key)})
    request = CallRequest(
        tool_name="payments__send",
        arguments={**args, "requestVC": vc.request_vc(args=args, key=key)},
        server_name="payments",
    )
    anonymous = await policy.check(request)
    assert not anonymous.allowed and "could not be assembled" in anonymous.reason
    named = await policy.check(__import__("dataclasses").replace(request, principal=PARENT))
    assert named.allowed, named.reason


async def test_a_claim_the_token_did_not_carry_fails_closed(rewritten_bundle, key):
    plan, manifest = _with_caller("acr")
    bundle = PolicyBundle.load(rewritten_bundle(MINIMAL_SPEND, plan=plan, manifest=manifest))
    with pytest.raises(FetchError, match="carries no 'acr'"):
        await FetchExecutor().assemble(bundle.fetchplan, _ctx(key, PARENT))


@pytest.mark.parametrize("field", ["token", "email", None])
def test_load_refuses_a_caller_field_the_principal_does_not_have(rewritten_bundle, field):
    def plan(doc):
        params = {"field": field} if field is not None else {}
        doc["entries"].append({"field": "who", "source": {"kind": "caller", "params": params}, "schema": {}})

    with pytest.raises(DerivePlanError, match="'caller' source must name one of"):
        PolicyBundle.load(rewritten_bundle(MINIMAL_SPEND, plan=plan))


def test_a_config_declared_bundle_may_read_the_caller(rewritten_bundle, tmp_path, key):
    """``caller`` needs no code from the deployment, unlike ``wallet``, so the
    no-Python form accepts it."""
    plan, manifest = _with_caller("sub")
    bundle_dir = rewritten_bundle(MINIMAL_SPEND, plan=plan, manifest=manifest)
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "mcpServers": {"payments": {"command": sys.executable, "args": [PAYMENTS_SERVER]}},
        "filters": {"policy_bundles": {"payments": {
            "path": str(bundle_dir), "config": {"requesterJwk": vc.public_jwk(key)},
        }}},
    }))
    create_server(load_config(config_path))  # no refusal

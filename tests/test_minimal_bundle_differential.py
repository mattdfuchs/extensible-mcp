# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The smallest bundle in the corpus, three ways, one verdict.

``minimal_spend`` (Rego under wasmtime), ``cel_minimal_spend`` (CEL in
process) and ``cedar_minimal_spend`` (Cedar over a host-derived witness set)
are the bundle the README's "Authoring a bundle" section walks through: one
signed request, one spending cap, five conditions. This file is what lets
the README quote them as one policy rather than three — every scenario runs
through the real ``WasmPolicyFilter`` on each twin and the three verdicts,
rendered denials and failed-check id sets are compared.

There is one denial scenario per condition, each naming the id it expects,
so a condition that silently stopped failing on one engine fails one named
test here. The rendered text the README quotes is asserted verbatim, so the
README cannot drift from what the proxy says.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.fetchplan import FetchContext, FetchExecutor
from extensible_mcp.types import CallRequest
from extensible_mcp.wasm_filter import WasmPolicyFilter
from tests import vc_helpers as vc

FIXTURES = Path(__file__).parent / "fixtures"
BUNDLES = {
    "rego": "minimal_spend",
    "cel": "cel_minimal_spend",
    "cedar": "cedar_minimal_spend",
}
IDS = {
    "solo.request_vc.signed_by",
    "solo.request_vc.within_window",
    "solo.request_vc.action_matches",
    "solo.request_vc.arguments_matches",
    "solo.arguments.amount_cents_at_most",
}
NOW = 100


@pytest.fixture(scope="module")
def key():
    return vc.new_key()


@pytest.fixture(scope="module")
def stranger():
    return vc.new_key()


@pytest.fixture(scope="module")
def bundles():
    return {engine: PolicyBundle.load(FIXTURES / name, name=name)
            for engine, name in BUNDLES.items()}


@dataclass(frozen=True)
class Scenario:
    allow: bool
    amount: int = 500
    tool: str = "payments__send"
    now: int = NOW
    tamper: bool = False
    signer: str = "key"                         # "key" | "stranger"
    signed_arguments: dict[str, Any] | None = None  # what the VC binds, if not the call's
    expect_ids: frozenset[str] = field(default_factory=frozenset)


SCENARIOS: dict[str, Scenario] = {
    "under_the_cap_allows": Scenario(allow=True),
    "over_the_cap": Scenario(
        allow=False, amount=5000,
        expect_ids=frozenset({"solo.arguments.amount_cents_at_most"})),
    "tampered_signature": Scenario(
        allow=False, tamper=True,
        expect_ids=frozenset({"solo.request_vc.signed_by"})),
    "signed_by_a_key_the_deployment_does_not_trust": Scenario(
        allow=False, signer="stranger",
        expect_ids=frozenset({"solo.request_vc.signed_by"})),
    "request_outside_its_window": Scenario(
        allow=False, now=10_000_000_000,
        expect_ids=frozenset({"solo.request_vc.within_window"})),
    "action_mismatch": Scenario(
        allow=False, tool="payments__transfer",
        expect_ids=frozenset({"solo.request_vc.action_matches"})),
    "signed_arguments_are_not_the_call_arguments": Scenario(
        allow=False, signed_arguments={"amountCents": 500, "merchant": "someone-else"},
        expect_ids=frozenset({"solo.request_vc.arguments_matches"})),
}


def _evidence(key, stranger, s: Scenario) -> tuple[dict[str, Any], dict[str, Any]]:
    """The call's native arguments and the request VC that (should) bind them."""
    args = {"amountCents": s.amount, "merchant": "acme"}
    req = vc.request_vc(args=s.signed_arguments or args,
                        key=key if s.signer == "key" else stranger)
    if s.tamper:
        jws = req["jws"]
        req = {**req, "jws": jws[:-6] + ("A" if jws[-1] != "A" else "B") * 6}
    return args, req


def _config(key) -> dict[str, str]:
    return {"requesterJwk": vc.public_jwk(key)}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
async def test_three_engines_one_verdict(bundles, key, stranger, name):
    s = SCENARIOS[name]
    args, req = _evidence(key, stranger, s)
    verdicts = {}
    for engine, bundle in bundles.items():
        f = WasmPolicyFilter(bundle, config=_config(key), clock=lambda: s.now)
        call = CallRequest(tool_name=s.tool, arguments={**args, "requestVC": req},
                           server_name="payments")
        result = await f.check(call)
        verdicts[engine] = (result.allowed, None if result.allowed else result.reason)
        if result.allowed:
            assert result.arguments == args, "the credential is stripped, the call forwarded"

    assert len(set(verdicts.values())) == 1, verdicts
    (allowed, reason), = set(verdicts.values())
    assert allowed is s.allow, verdicts
    if not allowed:
        assert reason and "could not" not in reason, reason  # a denial, not a fault


@pytest.mark.parametrize("name", sorted(SCENARIOS))
async def test_three_engines_report_the_same_check_ids(bundles, key, stranger, name):
    s = SCENARIOS[name]
    args, req = _evidence(key, stranger, s)
    envelope = {"tool": s.tool.split("__", 1)[1], "arguments": args, "requestVC": req}
    ctx = FetchContext(envelope=envelope, config=_config(key), now=s.now, wallet=None)
    reported = {}
    for engine, bundle in bundles.items():
        assembled = await FetchExecutor().assemble(bundle.fetchplan, ctx)
        assert bundle.validate_input(assembled) == [], engine
        allowed = bundle.policy.query(assembled, bundle.allow_entrypoint) == [{"result": True}]
        out = bundle.policy.query(assembled, bundle.failed_checks_entrypoint)
        reported[engine] = (allowed, frozenset(out[0]["result"]))

    assert len(set(reported.values())) == 1, reported
    (allowed, ids), = set(reported.values())
    assert allowed is s.allow
    assert ids == s.expect_ids, (sorted(ids), sorted(s.expect_ids))


def test_every_condition_has_a_denial_scenario(bundles):
    """One named denial per check, so the differential's coverage is a fact
    about this file rather than a hope."""
    expected = frozenset().union(*(s.expect_ids for s in SCENARIOS.values()))
    assert expected == IDS
    for engine, bundle in bundles.items():
        guidance_ids = {c["id"] for t in bundle.guidance["tiers"] for c in t["checks"]}
        assert guidance_ids == IDS, engine
    assert bundles["cedar"].policy.expected_ids == IDS


# The denial the README quotes. Asserted byte for byte so the documentation
# cannot drift from the proxy; the sentence is the guidance's, the frame is
# the renderer's.
OVER_THE_CAP_DENIAL = (
    "Tool call denied by policy: no allowed path was satisfied. "
    "To succeed, satisfy every condition of one of these paths:\n"
    "- Path 1: required: input.arguments.amountCents <= 1000.\n"
    "Gather the missing evidence or adjust the call, then retry."
)


@pytest.mark.parametrize("engine", sorted(BUNDLES))
async def test_the_denial_the_readme_quotes(bundles, key, stranger, engine):
    s = SCENARIOS["over_the_cap"]
    args, req = _evidence(key, stranger, s)
    f = WasmPolicyFilter(bundles[engine], config=_config(key), clock=lambda: s.now)
    result = await f.check(CallRequest(tool_name=s.tool, arguments={**args, "requestVC": req},
                                       server_name="payments"))
    assert not result.allowed
    assert result.reason == OVER_THE_CAP_DENIAL

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The three-engine differential: the same signed evidence, three bundles,
one verdict.

``family_spend`` (Rego under wasmtime), ``cel_family_spend`` (CEL in-process)
and ``cedar_family_spend`` (Cedar's engine over host-derived witness sets),
plus ``cedar_family_spend_compact``, the same Cedar policy in the
permit-decides shape
are three notations of one teaching policy. The first two share their
manifest and fetch plan byte for byte; the Cedar bundle cannot, because
every cryptographic leaf is hoisted out of the policy into a ``derive``
entry. That is what makes this the stronger claim: it exercises the
input-shape translation rather than assuming it.

Every scenario is run through the real ``WasmPolicyFilter`` on each bundle
and the three verdicts are compared at two levels — the decision and the
*rendered* denial the model would see, and underneath it the set of check
ids each engine reports. Each scenario also states what the verdict must
be, so three engines agreeing on a wrong answer still fails.

**The denial cases carry the weight.** A hoist that booleanized a relation
would still allow everything it should allow; the failure is invisible on
the allow path and surfaces only as a *missing denial*. So there is one
denial scenario per relation the hoist moves — signature, trust-root
chaining, subject binding, validity window, request binding — each naming
the id it expects, so dropping one relation fails exactly one test.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import pytest

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.fetchplan import FetchContext, FetchExecutor
from extensible_mcp.types import CallRequest
from extensible_mcp.wasm_filter import WasmPolicyFilter
from tests import vc_helpers as vc

FIXTURES = Path(__file__).parent / "fixtures"
BUNDLES = {
    "rego": "family_spend",
    "cel": "cel_family_spend",
    "cedar": "cedar_family_spend",
    # The same Cedar policy in the permit-decides shape, derived from the
    # adopted file: a fourth twin, held to the same verdicts and ids.
    "cedar_compact": "cedar_family_spend_compact",
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


# -- evidence ---------------------------------------------------------------- #


def _table(key, **override):
    table = {
        vc.KID_DID: vc.membership(sub=vc.KID_DID, role="kid", key=key),
        vc.PARENT_DID: vc.membership(sub=vc.PARENT_DID, role="parent", key=key),
    }
    table.update(override)
    return table


def _lookup(table):
    async def lookup(subject: str):
        return table.get(subject)
    return lookup


def _dummy_authorization(req: dict) -> dict:
    """Shape-valid, never verifying: what a call below the solo limit sends
    on the two bundles whose manifests require the field."""
    return {
        "jws": req["jws"],
        "claims": {"jti": "r1", "iss": vc.PARENT_DID, "requestHash": "0" * 64,
                   "nbf": 0, "exp": 9999999999},
    }


def _arguments(key, stranger, *, amount: int, auth: str, tamper: bool) -> dict[str, Any]:
    args = {"amountCents": amount, "merchant": "acme"}
    req = vc.request_vc(args=args, key=key)
    if tamper:
        jws = req["jws"]
        req = {**req, "jws": jws[:-6] + ("A" if jws[-1] != "A" else "B") * 6}
    arguments: dict[str, Any] = {**args, "requestVC": req}
    if auth == "valid":
        arguments["authorizationVC"] = vc.authorization_vc(request_jws=req["jws"], key=key)
    elif auth == "dummy":
        arguments["authorizationVC"] = _dummy_authorization(req)
    elif auth == "other_request":
        # The helpers sign only the subject, so two requests yield the same
        # JWS bytes; bind to different bytes rather than different claims.
        arguments["authorizationVC"] = vc.authorization_vc(request_jws=req["jws"] + "x", key=key)
        assert arguments["authorizationVC"]["claims"]["requestHash"] != hashlib.sha256(
            req["jws"].encode()).hexdigest()
    elif auth == "stranger":
        arguments["authorizationVC"] = vc.authorization_vc(request_jws=req["jws"], key=stranger)
    elif auth == "garbage":
        arguments["authorizationVC"] = {**_dummy_authorization(req), "jws": "not.a.jws"}
    else:
        raise AssertionError(auth)
    return arguments


@dataclass(frozen=True)
class Scenario:
    allow: bool
    amount: int
    auth: str = "dummy"
    tamper: bool = False
    tool: str = "payments__send"
    now: int = NOW
    wallet: Callable[[Any, Any], dict] | None = None     # (key, stranger) -> table
    trust_root_of: str = "key"                            # "key" | "stranger"
    expect_ids: frozenset[str] = field(default_factory=frozenset)


SCENARIOS: dict[str, Scenario] = {
    "solo_allows": Scenario(allow=True, amount=500),
    "full_chain_allows": Scenario(allow=True, amount=5000, auth="valid"),
    "garbage_authorization_in_the_inapplicable_tier_still_allows":
        Scenario(allow=True, amount=400, auth="garbage"),
    "over_the_cap": Scenario(
        allow=False, amount=50000, auth="valid",
        expect_ids=frozenset({"full_chain.arguments.amount_cents_at_most"})),
    "over_the_solo_limit_without_a_real_authorization": Scenario(
        allow=False, amount=5000,
        expect_ids=frozenset({"solo.arguments.amount_cents_at_most",
                              "full_chain.request_vc.bound_to"})),
    "action_mismatch": Scenario(
        allow=False, amount=500, tool="payments__transfer",
        expect_ids=frozenset({"solo.request_vc.action_matches"})),
    # -- one denial per hoisted relation ------------------------------------ #
    "tampered_request_signature": Scenario(
        allow=False, amount=500, tamper=True,
        expect_ids=frozenset({"solo.request_vc.signed_by", "full_chain.request_vc.signed_by"})),
    "membership_not_signed_by_the_trust_root": Scenario(
        allow=False, amount=500,
        wallet=lambda key, stranger: _table(
            key, **{vc.KID_DID: vc.membership(sub=vc.KID_DID, role="kid", key=stranger)}),
        expect_ids=frozenset({"solo.requester_membership.signed_by"})),
    "membership_subject_is_not_the_requester": Scenario(
        allow=False, amount=500,
        wallet=lambda key, stranger: _table(
            key, **{vc.KID_DID: vc.membership(sub=vc.PARENT_DID, role="kid", key=key)}),
        expect_ids=frozenset({"solo.requester_membership.sub_matches"})),
    "request_outside_its_window": Scenario(
        allow=False, amount=500, now=10_000_000_000,
        expect_ids=frozenset({"solo.request_vc.within_window"})),
    "authorization_bound_to_another_request": Scenario(
        allow=False, amount=5000, auth="other_request",
        expect_ids=frozenset({"full_chain.request_vc.bound_to"})),
    "authorization_signed_by_a_stranger": Scenario(
        allow=False, amount=5000, auth="stranger",
        expect_ids=frozenset({"full_chain.authorization_vc.signed_by"})),
    "wrong_role": Scenario(
        allow=False, amount=500,
        wallet=lambda key, stranger: _table(
            key, **{vc.KID_DID: vc.membership(sub=vc.KID_DID, role="parent", key=key)}),
        expect_ids=frozenset({"solo.requester_membership.role_matches"})),
    "no_trust_root_key_verifies_anything": Scenario(
        allow=False, amount=500, trust_root_of="stranger",
        expect_ids=frozenset({"solo.request_vc.signed_by",
                              "solo.requester_membership.signed_by"})),
}


def _config(key, stranger, scenario: Scenario) -> dict[str, str]:
    root = key if scenario.trust_root_of == "key" else stranger
    return {"trustRootDID": vc.TRUST_DID, "trustRootJwk": vc.public_jwk(root)}


def _wallet(key, stranger, scenario: Scenario):
    table = scenario.wallet(key, stranger) if scenario.wallet else _table(key)
    return _lookup(table)


# -- the differential -------------------------------------------------------- #


@pytest.mark.parametrize("name", sorted(SCENARIOS))
async def test_three_engines_one_verdict(bundles, key, stranger, name):
    scenario = SCENARIOS[name]
    arguments = _arguments(key, stranger, amount=scenario.amount,
                           auth=scenario.auth, tamper=scenario.tamper)
    verdicts = {}
    for engine, bundle in bundles.items():
        f = WasmPolicyFilter(
            bundle,
            config=_config(key, stranger, scenario),
            wallet_lookup=_wallet(key, stranger, scenario),
            clock=lambda: scenario.now,
        )
        call = CallRequest(tool_name=scenario.tool, arguments=dict(arguments),
                           server_name="payments")
        result = await f.check(call)
        verdicts[engine] = (result.allowed, None if result.allowed else result.reason)

    assert len(set(verdicts.values())) == 1, verdicts
    (allowed, reason), = set(verdicts.values())
    assert allowed is scenario.allow, verdicts
    if not allowed:
        assert reason and "could not" not in reason, reason  # a denial, not a fault


@pytest.mark.parametrize("name", sorted(SCENARIOS))
async def test_three_engines_report_the_same_check_ids(bundles, key, stranger, name):
    """Underneath the rendered reason: each engine's ``failed_checks`` over
    its own assembled input. Rego reports an undefined check as absent, CEL
    drops a guarded one, Cedar drops its ``@assembly`` forbids — three
    mechanisms, one set."""
    scenario = SCENARIOS[name]
    arguments = _arguments(key, stranger, amount=scenario.amount,
                           auth=scenario.auth, tamper=scenario.tamper)
    native = {k: v for k, v in arguments.items() if k not in ("requestVC", "authorizationVC")}
    envelope = {"tool": scenario.tool.split("__", 1)[1], "arguments": native,
                "requestVC": arguments["requestVC"],
                "authorizationVC": arguments["authorizationVC"]}
    ctx = FetchContext(envelope=envelope, config=_config(key, stranger, scenario),
                       now=scenario.now, wallet=_wallet(key, stranger, scenario))
    reported = {}
    for engine, bundle in bundles.items():
        assembled = await FetchExecutor().assemble(bundle.fetchplan, ctx)
        assert bundle.validate_input(assembled) == [], engine
        allowed = bundle.policy.query(assembled, bundle.allow_entrypoint) == [{"result": True}]
        out = bundle.policy.query(assembled, bundle.failed_checks_entrypoint)
        reported[engine] = (allowed, frozenset(out[0]["result"]))

    assert len(set(reported.values())) == 1, reported
    (allowed, ids), = set(reported.values())
    assert allowed is scenario.allow
    assert scenario.expect_ids <= ids, (sorted(scenario.expect_ids - ids), sorted(ids))
    assert allowed == (not ids), "allow ⟺ failed_checks == [] holds on every engine"


#: One id per relation the hoist moves out of the policy. Each must be the
#: expected reason of some denial scenario above, so that a hoist which
#: silently booleanized that relation fails a named test rather than vanishing.
REQUIRED_DENIALS = frozenset({
    "solo.request_vc.signed_by",               # the request's own signature
    "solo.requester_membership.signed_by",     # membership chains to the trust root
    "solo.requester_membership.sub_matches",   # membership subject is the issuer
    "solo.request_vc.within_window",           # validity window
    "full_chain.request_vc.bound_to",          # authorization bound to this request
    "full_chain.authorization_vc.signed_by",   # the authorization's own signature
})


def test_every_hoisted_relation_has_a_denial_scenario(bundles):
    """The coverage the differential rests on, asserted rather than assumed."""
    cedar = bundles["cedar"]
    derived = [e for e in cedar.fetchplan["entries"] if e["source"]["kind"] == "derive"]
    assert len(derived) == 5, "the Cedar bundle's hoisted leaves changed; revisit REQUIRED_DENIALS"
    expected = frozenset().union(*(s.expect_ids for s in SCENARIOS.values()))
    assert REQUIRED_DENIALS <= expected, sorted(REQUIRED_DENIALS - expected)
    assert REQUIRED_DENIALS <= cedar.policy.expected_ids

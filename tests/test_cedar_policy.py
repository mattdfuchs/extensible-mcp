# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The Cedar engine over the ``cedar_family_spend`` bundle.

Three properties of Cedar become tests here; what this file does not cover
— that the bundle decides what its Rego and CEL siblings decide — is
``test_three_engine_differential.py``.

- **Forbid-only means an empty policy set allows everything.** The loader
  refuses a set that does not carry exactly the forbids ``expected_ids.json``
  lists, and the tests pin that cedarpy on its own *would* allow the bundle
  the loader refuses — otherwise the refusal is untested belt-and-braces.
- **A condition that raises skips its policy, and a skipped forbid is a
  permit.** An evaluation diagnostic is therefore a fault that fails closed,
  never a denial with noise; again pinned against cedarpy's own answer.
- **An ``@assembly`` forbid carries no ``@id``.** A fired one is dropped from
  ``failed_checks`` rather than rendered as Cedar's positional label, and
  the absent credential is explained from the guard metadata instead.

The rest mirrors ``test_cel_policy.py``'s filter-level assertions, so the
three engine test files read the same way.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
from pathlib import Path

import pytest

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.cedar_policy import REQUEST_HEAD, CedarPolicy, CedarPolicyError
from extensible_mcp.fetchplan import FetchContext, FetchExecutor, default_resolvers
from extensible_mcp.types import CallRequest
from extensible_mcp.wasm_filter import WasmPolicyFilter
from extensible_mcp.wasm_policy import PolicyEvaluationError
from tests import vc_helpers as vc

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE_DIR = FIXTURES / "cedar_family_spend"


@pytest.fixture(scope="module")
def key():
    return vc.new_key()


@pytest.fixture
def bundle():
    return PolicyBundle.load(FIXTURE_DIR, name="cedar_family_spend")


def _memberships(key):
    table = {
        vc.KID_DID: vc.membership(sub=vc.KID_DID, role="kid", key=key),
        vc.PARENT_DID: vc.membership(sub=vc.PARENT_DID, role="parent", key=key),
    }

    async def lookup(subject: str):
        return table.get(subject)

    return lookup


def _filter(bundle, key, **overrides):
    kwargs = dict(
        config={"trustRootDID": vc.TRUST_DID, "trustRootJwk": vc.public_jwk(key)},
        wallet_lookup=_memberships(key),
        clock=lambda: 100,
    )
    kwargs.update(overrides)
    return WasmPolicyFilter(bundle, **kwargs)


def _call(key, *, amount: int, with_auth: bool | None, tool="payments__send") -> CallRequest:
    """``with_auth``: ``True`` a valid parent authorization, ``False`` the
    shape-valid dummy the CEL/Rego tests send, ``None`` absent entirely —
    which only this bundle's manifest admits (its ``authorizationVC`` is
    guarded, not required)."""
    args = {"amountCents": amount, "merchant": "acme"}
    req = vc.request_vc(args=args, key=key)
    arguments = {**args, "requestVC": req}
    if with_auth is True:
        arguments["authorizationVC"] = vc.authorization_vc(request_jws=req["jws"], key=key)
    elif with_auth is False:
        arguments["authorizationVC"] = {
            "jws": req["jws"],
            "claims": {"jti": "r1", "iss": vc.PARENT_DID, "requestHash": "0" * 64,
                       "nbf": 0, "exp": 9999999999},
        }
    return CallRequest(tool_name=tool, arguments=arguments, server_name="payments")


def _assert_fault_logged_not_leaked(caplog, result, tool_name):
    faults = [r for r in caplog.records
              if r.levelno == logging.WARNING and "(failing closed)" in r.getMessage()]
    assert len(faults) == 1, [r.getMessage() for r in caplog.records]
    assert repr(tool_name) in faults[0].getMessage()


# -- PolicyBundle.load() picks the Cedar engine from directory contents ----- #


def test_load_dispatches_to_cedar_engine(bundle):
    assert isinstance(bundle.policy, CedarPolicy)
    assert bundle.package == "cedar_family_spend"
    assert bundle.policy.entrypoints() == [
        "cedar_family_spend/allow", "cedar_family_spend/failed_checks",
    ]
    assert bundle.has_failed_checks()
    assert not bundle.has_deny_reason()  # like CEL: denials render through guidance


def test_loader_found_a_forbid_for_every_guidance_id_and_every_tier(bundle):
    ids = {c["id"] for t in bundle.guidance["tiers"] for c in t["checks"]}
    assert bundle.policy.expected_ids == ids
    assert bundle.policy.assembly_tiers == {"solo", "full_chain"}


def test_bundle_exposes_credential_fields(bundle):
    assert set(bundle.credential_fields()) == {"requestVC", "authorizationVC"}


# -- load-time refusals: the empty-policy-set hazard ------------------------ #

_ANNOTATED_FORBID = r"\n(?:@[a-z]+\([^)]*\)\n)*forbid \(.*?\};\n"


def _without(text: str, annotation: str) -> str:
    """The policy text minus the one annotated forbid that starts with ``annotation``."""
    new, n = re.subn(re.escape(annotation) + _ANNOTATED_FORBID, "", text, count=1, flags=re.S)
    assert n == 1, annotation
    return new


def _variant(tmp_path, *, policy=None, expected=None, drop_expected=False) -> Path:
    d = tmp_path / "cedar_variant"
    shutil.copytree(FIXTURE_DIR, d)
    if policy is not None:
        (d / "policy.cedar").write_text(policy)
    if expected is not None:
        (d / "expected_ids.json").write_text(json.dumps(expected))
    if drop_expected:
        (d / "expected_ids.json").unlink()
    return d


def _policy_text() -> str:
    return (FIXTURE_DIR / "policy.cedar").read_text()


def test_the_bare_permit_is_the_hazard_the_loader_exists_for(tmp_path):
    """cedarpy alone allows a policy set with no forbids. The loader is what
    stands between a half-loaded bundle and a silent permit, so pin both
    halves: Cedar's answer, and the refusal."""
    import cedarpy

    bare = "permit (principal, action, resource);\n"
    res = cedarpy.is_authorized({**REQUEST_HEAD, "context": {}}, bare, [])
    assert res.decision == cedarpy.Decision.Allow
    with pytest.raises(CedarPolicyError, match="silent permit"):
        PolicyBundle.load(_variant(tmp_path, policy=bare))


def test_dropping_one_leaf_forbid_is_refused_at_load(tmp_path):
    text = _without(_policy_text(), '@id("solo.request_vc.signed_by")')
    with pytest.raises(CedarPolicyError, match=r"missing \['solo\.request_vc\.signed_by'\]"):
        PolicyBundle.load(_variant(tmp_path, policy=text))


def test_dropping_an_assembly_forbid_is_refused_at_load(tmp_path):
    """Counting ``ids`` alone would pass a bundle whose incompleteness guards
    were dropped — the exact shape that allows a tier whose inputs are all
    absent."""
    text = _without(_policy_text(), '@assembly("full_chain")')
    with pytest.raises(CedarPolicyError, match=r"@assembly.*missing \['full_chain'\]"):
        PolicyBundle.load(_variant(tmp_path, policy=text))


def test_an_unexpected_id_is_refused_at_load(tmp_path):
    text = _policy_text() + (
        '\n@id("solo.made_up")\nforbid (principal, action, resource) when { false };\n'
    )
    with pytest.raises(CedarPolicyError, match=r"unexpected \['solo\.made_up'\]"):
        PolicyBundle.load(_variant(tmp_path, policy=text))


def test_a_forbid_with_no_annotation_is_refused_at_load(tmp_path):
    text = _policy_text() + "\nforbid (principal, action, resource) when { false };\n"
    with pytest.raises(CedarPolicyError, match="neither @id nor @assembly"):
        PolicyBundle.load(_variant(tmp_path, policy=text))


def test_missing_expected_ids_is_refused_at_load(tmp_path):
    with pytest.raises(CedarPolicyError, match="expected_ids.json"):
        PolicyBundle.load(_variant(tmp_path, drop_expected=True))


def test_a_malformed_policy_set_is_refused_not_loaded(tmp_path):
    """cedarpy reports a parse error as ``NoDecision`` with the message in the
    diagnostics rather than raising; the loader must not get as far as asking."""
    import cedarpy

    broken = "permit (principal, action, resource) when { 1 + };"
    res = cedarpy.is_authorized({**REQUEST_HEAD, "context": {}}, broken, [])
    assert res.decision == cedarpy.Decision.NoDecision
    with pytest.raises(CedarPolicyError, match="does not parse"):
        PolicyBundle.load(_variant(tmp_path, policy=broken))


# -- evaluation: the filter path, mirroring test_cel_policy.py -------------- #


async def test_allows_and_strips_credential_args(bundle, key):
    result = await _filter(bundle, key).check(_call(key, amount=500, with_auth=False))
    assert result.allowed is True
    assert result.arguments == {"amountCents": 500, "merchant": "acme"}


async def test_full_chain_allows(bundle, key):
    result = await _filter(bundle, key).check(_call(key, amount=5000, with_auth=True))
    assert result.allowed is True


async def test_tampered_request_denies_with_the_guidance_sentence(bundle, key):
    call = _call(key, amount=500, with_auth=False)
    jws = call.arguments["requestVC"]["jws"]
    call.arguments["requestVC"]["jws"] = jws[:-6] + ("A" if jws[-1] != "A" else "B") * 6
    result = await _filter(bundle, key).check(call)
    assert result.allowed is False
    assert "signature is invalid" in result.reason


async def test_over_limit_without_auth_denies(bundle, key):
    result = await _filter(bundle, key).check(_call(key, amount=5000, with_auth=False))
    assert result.allowed is False


async def test_action_mismatch_denies(bundle, key):
    call = _call(key, amount=500, with_auth=False, tool="payments__transfer")
    assert (await _filter(bundle, key).check(call)).allowed is False


async def test_absent_authorization_is_explained_from_the_guard_not_a_positional_id(bundle, key):
    """Above the solo limit with no authorization at all: the full-chain tier
    is incomplete, so its ``@assembly`` forbid fires. That forbid has no
    ``@id``; the renderer names the missing credential from ``call_guards``
    and no ``policyN`` label reaches the model."""
    result = await _filter(bundle, key).check(_call(key, amount=5000, with_auth=None))
    assert result.allowed is False
    assert "provide `authorizationVC`" in result.reason
    assert re.search(r"\bpolicy\d+\b", result.reason) is None


async def test_missing_credential_fails_closed(bundle, key, caplog):
    call = _call(key, amount=500, with_auth=False)
    del call.arguments["requestVC"]
    with caplog.at_level(logging.WARNING, logger="extensible_mcp.wasm_filter"):
        result = await _filter(bundle, key).check(call)
    assert result.allowed is False
    assert "could not be assembled" in result.reason
    _assert_fault_logged_not_leaked(caplog, result, call.tool_name)


# -- evaluation: the engine's own contract ---------------------------------- #


def test_assembly_only_denial_reports_no_ids(bundle):
    """Empty input: every tier is incomplete and nothing is present-and-false,
    so the only policies that fire are the two ``@assembly`` forbids. Cedar
    reports two reasons; ``failed_checks`` reports none, and the decision is
    still a denial."""
    import cedarpy

    res = cedarpy.is_authorized({**REQUEST_HEAD, "context": {}}, _policy_text(), [])
    assert res.decision == cedarpy.Decision.Deny
    assert len(res.diagnostics.reasons) == 2
    assert bundle.policy.query({}, bundle.allow_entrypoint) == [{"result": False}]
    assert bundle.policy.query({}, bundle.failed_checks_entrypoint) == [{"result": []}]


def test_an_evaluation_diagnostic_is_a_fault_not_a_permit(tmp_path):
    """A hand-written forbid that reads an attribute without ``has``: Cedar
    skips it and **allows**, with the error in the diagnostics. The engine
    raises instead. The supplier proves its emitted conditions cannot raise;
    this is what happens when a bundle without that proof is loaded."""
    import cedarpy

    unsafe = (
        "permit (principal, action, resource);\n"
        '@id("t.leaf")\nforbid (principal, action, resource) when { context.missing == 1 };\n'
        '@assembly("t")\nforbid (principal, action, resource) when { !(context has missing) && false };\n'
    )
    res = cedarpy.is_authorized({**REQUEST_HEAD, "context": {}}, unsafe, [])
    assert res.decision == cedarpy.Decision.Allow and res.diagnostics.errors
    d = _variant(tmp_path, policy=unsafe,
                 expected={"ids": ["t.leaf"], "tiers": [{"tier": "t", "ids": ["t.leaf"]}]})
    policy = CedarPolicy(d / "policy.cedar")
    with pytest.raises(PolicyEvaluationError, match="skipped forbid is a permit"):
        policy.query({}, "cedar_variant/allow")


def test_a_value_cedar_cannot_represent_is_a_fault(bundle):
    """``null`` and a non-integral number have no Cedar value; cedarpy answers
    ``NoDecision``. Not a denial: a fault, so the filter fails closed and logs."""
    for bad in ({"now": None}, {"now": 1.5}, {"now": 2**70}):
        with pytest.raises(PolicyEvaluationError):
            bundle.policy.query(bad, bundle.allow_entrypoint)


def test_reserved_context_keys_are_refused(bundle):
    """Cedar's JSON reader turns an object with an ``__entity`` or ``__extn``
    key into an entity reference or extension value, not a record."""
    with pytest.raises(PolicyEvaluationError, match="__entity"):
        bundle.policy.query(
            {"requestVC": {"claims": {"__entity": {"type": "Caller", "id": "x"}}}},
            bundle.allow_entrypoint,
        )


async def test_reserved_key_inside_an_open_claims_object_fails_closed(bundle, key, caplog):
    """The manifest's claims objects are open, so a key no check reads passes
    schema validation and reaches the engine. The engine refuses it, and the
    model sees a rendered fault rather than the key."""
    call = _call(key, amount=500, with_auth=False)
    call.arguments["requestVC"]["claims"]["__extn"] = {"fn": "ip", "arg": "10.0.0.1"}
    with caplog.at_level(logging.WARNING, logger="extensible_mcp.wasm_filter"):
        result = await _filter(bundle, key).check(call)
    assert result.allowed is False
    assert "__extn" not in result.reason
    _assert_fault_logged_not_leaked(caplog, result, call.tool_name)


def test_unknown_entrypoint_raises(bundle):
    with pytest.raises(PolicyEvaluationError, match="unknown entrypoint"):
        bundle.policy.query({}, "cedar_family_spend/deny_reason")


# -- the derivation contract: the proxy's half of the Cedar guarantee ------- #


async def test_fold_emits_no_witness_for_a_truthy_answer_that_is_not_true():
    """``contract.json``'s obligation is exactness: the witness set is the
    candidates for which the primitive *holds*, and no other value. The
    direction that matters is over-inclusion — a set that is too large makes
    a forbid fail to fire, so Cedar allows where the source denies. The fold
    collects on ``is True``, by identity and not by truthiness."""
    answers = {"k1": 1, "k2": "yes", "k3": [True], "k4": {"ok": True}, "k5": True}

    def pseudo_verify(_message, key):
        return answers[key]

    plan = {
        "entries": [
            {"field": "message", "source": {"kind": "config"}},
            {"field": "candidates", "source": {"kind": "config"}},
            {"field": "witnesses", "source": {
                "kind": "derive", "fn": "pseudo_verify",
                "over": {"$input": "candidates"},
                "args": [{"$input": "message"}, {"$item": "key"}],
                "project": "key",
            }},
        ],
    }
    ctx = FetchContext(config={
        "message": "m",
        "candidates": [{"key": k} for k in sorted(answers)],
    })
    executor = FetchExecutor(default_resolvers(primitives={"pseudo_verify": pseudo_verify}))
    assembled = await executor.assemble(plan, ctx)
    assert assembled["witnesses"] == ["k5"]

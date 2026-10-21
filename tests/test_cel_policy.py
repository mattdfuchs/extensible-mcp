# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Real (not paper) parity proof for the CEL policy engine: the exact same
scenarios and assertions as test_wasm_filter.py's family_spend suite, run
against a hand-authored CEL bundle instead of the OPA/Rego one — same
PolicyBundle.load(), same WasmPolicyFilter, same wallet_lookup/config wiring.
If this file's tests pass, CelPolicy is a real drop-in PolicyEngine, not
just a Protocol on paper.

Plus the one test paper analysis alone couldn't settle: that an unguarded
absent field fails closed (PolicyEvaluationError), never a silent false —
the central design decision in NOTES.md's CEL section."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.cel_policy import CelPolicy, default_cel_functions
from extensible_mcp.types import CallRequest
from extensible_mcp.wasm_filter import WasmPolicyFilter
from extensible_mcp.wasm_policy import PolicyEvaluationError
from tests import vc_helpers as vc

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "cel_family_spend"


@pytest.fixture(scope="module")
def key():
    return vc.new_key()


@pytest.fixture
def bundle():
    return PolicyBundle.load(FIXTURE_DIR, name="cel_family_spend")


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


def _call(key, *, amount: int, with_auth: bool, tool="payments__send") -> CallRequest:
    args = {"amountCents": amount, "merchant": "acme"}
    req = vc.request_vc(args=args, key=key)
    arguments = {**args, "requestVC": req}
    if with_auth:
        arguments["authorizationVC"] = vc.authorization_vc(request_jws=req["jws"], key=key)
    else:
        arguments["authorizationVC"] = {
            "jws": req["jws"],
            "claims": {"jti": "r1", "iss": vc.PARENT_DID, "requestHash": "0" * 64,
                       "nbf": 0, "exp": 9999999999},
        }
    return CallRequest(tool_name=tool, arguments=arguments, server_name="payments")


# -- PolicyBundle.load() picks the CEL engine from directory contents ------- #


def test_load_dispatches_to_cel_engine(bundle):
    assert isinstance(bundle.policy, CelPolicy)
    assert bundle.package == "policybundle.examples.family_spend"
    assert bundle.allow_entrypoint.endswith("/allow")
    assert bundle.has_failed_checks()
    assert not bundle.has_deny_reason()  # CEL bundles have no English deny_reason


def test_bundle_exposes_credential_fields(bundle):
    assert set(bundle.credential_fields()) == {"requestVC", "authorizationVC"}


# -- exact mirrors of test_wasm_filter.py's assertions, real parity -------- #


async def test_allows_and_strips_credential_args(bundle, key):
    f = _filter(bundle, key)
    result = await f.check(_call(key, amount=500, with_auth=False))
    assert result.allowed is True
    assert result.arguments == {"amountCents": 500, "merchant": "acme"}
    assert "requestVC" not in result.arguments


async def test_full_chain_allows(bundle, key):
    f = _filter(bundle, key)
    result = await f.check(_call(key, amount=5000, with_auth=True))
    assert result.allowed is True


async def test_tampered_request_denies_with_reason(bundle, key):
    f = _filter(bundle, key)
    call = _call(key, amount=500, with_auth=False)
    jws = call.arguments["requestVC"]["jws"]
    call.arguments["requestVC"]["jws"] = jws[:-6] + ("A" if jws[-1] != "A" else "B") * 6
    result = await f.check(call)
    assert result.allowed is False
    assert "signature is invalid" in result.reason


async def test_over_limit_without_auth_denies(bundle, key):
    f = _filter(bundle, key)
    result = await f.check(_call(key, amount=5000, with_auth=False))
    assert result.allowed is False


async def test_action_mismatch_denies(bundle, key):
    f = _filter(bundle, key)
    call = _call(key, amount=500, with_auth=False, tool="payments__transfer")
    result = await f.check(call)
    assert result.allowed is False


async def test_missing_credential_fails_closed(bundle, key, caplog):
    f = _filter(bundle, key)
    call = _call(key, amount=500, with_auth=False)
    del call.arguments["requestVC"]
    with caplog.at_level(logging.WARNING, logger="extensible_mcp.wasm_filter"):
        result = await f.check(call)
    assert result.allowed is False
    assert "could not be assembled" in result.reason
    _assert_fault_logged_not_leaked(caplog, result, call.tool_name)


async def test_broken_trust_root_fails_closed(bundle, key, caplog):
    f = _filter(bundle, key, config={"trustRootDID": vc.TRUST_DID, "trustRootJwk": "garbage"})
    call = _call(key, amount=500, with_auth=False)
    with caplog.at_level(logging.WARNING, logger="extensible_mcp.wasm_filter"):
        result = await f.check(call)
    assert result.allowed is False
    assert "failing closed" in result.reason
    _assert_fault_logged_not_leaked(caplog, result, call.tool_name)


def _assert_fault_logged_not_leaked(caplog, result, tool_name):
    """Same contract as the Rego filter test of the same name: the fault is
    logged at ``warning`` naming the tool and carrying the exception, and the
    exception is not in the reason the model sees."""
    faults = [r for r in caplog.records
              if r.levelno == logging.WARNING and "(failing closed)" in r.getMessage()]
    assert len(faults) == 1, [r.getMessage() for r in caplog.records]
    logged = faults[0].getMessage()
    assert repr(tool_name) in logged
    exception_text = logged.split("(failing closed): ", 1)[1]
    assert exception_text
    assert exception_text not in result.reason
    assert result.reason.endswith("(failing closed; the detail is in the proxy log).")


async def test_arguments_binding_enforced(bundle, key):
    f = _filter(bundle, key)
    call = _call(key, amount=500, with_auth=False)
    call.arguments["amountCents"] = 999
    result = await f.check(call)
    assert result.allowed is False


async def test_denial_is_disjunctive_across_tiers(bundle, key):
    # Over-limit without a valid authorization: tier 0 fails on the amount
    # bound, tier 1 fails on the (garbage) authorization binding -- the
    # renderer must show both paths, exactly like the OPA-backed bundle.
    f = _filter(bundle, key)
    result = await f.check(_call(key, amount=5000, with_auth=False))
    assert result.allowed is False
    assert "- Path 1:" in result.reason and "- Path 2:" in result.reason
    assert "1000" in result.reason
    assert "retry" in result.reason


# --------------------------------------------------------------------------- #
# The central design decision, proven directly against CelPolicy: any
# exception during evaluation -- including an unguarded absent field --
# fails closed as PolicyEvaluationError, never a silent False.
# --------------------------------------------------------------------------- #


def _write_minimal_bundle(tmp_path: Path, *, guarded: bool) -> Path:
    d = tmp_path / "minimal"
    d.mkdir()
    expr = (
        "has(input.approval) && input.approval.amountCents <= 1000"
        if guarded
        else "input.approval.amountCents <= 1000"
    )
    (d / "checks.cel.json").write_text(json.dumps({
        "engine": "cel-v1",
        "package": "policybundle.examples.minimal",
        "tiers": [{"tier": 0, "checks": ["solo.approval.amount_cents_at_most"]}],
        "checks": {"solo.approval.amount_cents_at_most": expr},
    }))
    return d


def test_unguarded_absent_field_fails_closed(tmp_path):
    policy = CelPolicy(_write_minimal_bundle(tmp_path, guarded=False) / "checks.cel.json")
    with pytest.raises(PolicyEvaluationError):
        policy.query({"tool": "spend"}, "policybundle.examples.minimal/allow")


def test_guarded_absent_field_denies_cleanly(tmp_path):
    policy = CelPolicy(_write_minimal_bundle(tmp_path, guarded=True) / "checks.cel.json")
    result = policy.query({"tool": "spend"}, "policybundle.examples.minimal/allow")
    assert result == [{"result": False}]


def test_guarded_present_field_allows(tmp_path):
    policy = CelPolicy(_write_minimal_bundle(tmp_path, guarded=True) / "checks.cel.json")
    result = policy.query(
        {"tool": "spend", "approval": {"amountCents": 500}},
        "policybundle.examples.minimal/allow",
    )
    assert result == [{"result": True}]


def test_custom_builtin_raising_host_error_fails_closed(tmp_path):
    # A registered builtin raising (mirrors HostBuiltinError from a bad JWK)
    # must fail closed, not be silently treated as "check failed".
    from extensible_mcp.wasm_policy import HostBuiltinError

    def _boom(x):
        raise HostBuiltinError("bad key material")

    d = tmp_path / "boom"
    d.mkdir()
    (d / "checks.cel.json").write_text(json.dumps({
        "engine": "cel-v1", "package": "policybundle.examples.boom",
        "tiers": [{"tier": 0, "checks": ["solo.input.boom"]}],
        "checks": {"solo.input.boom": "boom(input.x)"},
    }))
    policy = CelPolicy(d / "checks.cel.json", functions={"boom": _boom})
    with pytest.raises(PolicyEvaluationError):
        policy.query({"x": "y"}, "policybundle.examples.boom/allow")


def test_default_cel_functions_includes_webauthn_only_when_configured():
    assert "verify_webauthn" not in default_cel_functions()
    assert "verify_webauthn" in default_cel_functions(webauthn_rp_id="example.com")


def test_verify_ed25519_raw_available_and_matches_the_plain_builtin():
    """The CEL adapter is a thin celtypes wrapper — same result as the plain
    Python builtin it delegates to (the merchant-invoice check)."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    functions = default_cel_functions()
    assert "verify_ed25519_raw" in functions

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    message = '{"merchantId":"dominos","totalCents":400}'
    signature = private_key.sign(message.encode())
    key_b64url = base64.urlsafe_b64encode(public_key.public_bytes_raw()).rstrip(b"=").decode()
    sig_b64url = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

    assert bool(functions["verify_ed25519_raw"](message, sig_b64url, key_b64url)) is True
    assert bool(functions["verify_ed25519_raw"]("tampered", sig_b64url, key_b64url)) is False


def test_parse_json_and_base64url_decode_available():
    """CEL twins of Rego's json.unmarshal / base64url.decode —
    needed because a bundle parses signed evidence (an invoice, a WebAuthn
    clientDataJSON) *inside* the policy rather than the proxy pre-parsing
    it, which would sever the parsed fields from the signature covering
    the original bytes."""
    import base64

    from celpy import celtypes

    functions = default_cel_functions()
    assert "parse_json" in functions
    assert "base64url_decode" in functions

    parsed = functions["parse_json"](celtypes.StringType('{"merchantId":"dominos","totalCents":400}'))
    assert dict(parsed) == {"merchantId": "dominos", "totalCents": 400}

    encoded = base64.urlsafe_b64encode(b'{"origin":"https://x"}').rstrip(b"=").decode()
    decoded = functions["base64url_decode"](celtypes.StringType(encoded))
    assert str(decoded) == '{"origin":"https://x"}'


def test_parse_json_malformed_denies_without_aborting(tmp_path):
    """Unparseable evidence fails the checks that read it and nothing else.

    ``parse_json`` returns the :func:`~extensible_mcp.cel_policy.undefined_evidence`
    subclass, which cel-python threads through the rest of the expression as
    a value, so the check lands as a reported failure with its authored
    sentence intact. It used to raise, which escaped the evaluator and
    aborted the whole query — denying as an engine fault, with no guidance
    and no retry hint, and taking down tiers that never read the field. Rego
    never behaved that way: ``json.unmarshal`` is an OPA native whose
    undefined stays inside the rule body that read it.

    Isolated to a single-check bundle on purpose. The earlier version of this
    test patched one check into a full fixture and queried it with an
    otherwise-empty input, so the ``PolicyEvaluationError`` it asserted came
    from a *different* check reading an absent field — it passed without
    exercising ``parse_json`` at all."""
    policy = CelPolicy(
        _write_check(tmp_path, 'parse_json(input.notJson) != null'),
        functions=default_cel_functions(),
    )
    entry = "policybundle.examples.nonbool"
    assert policy.query({"notJson": "not valid json"}, f"{entry}/allow") == [
        {"result": False}
    ]
    assert policy.query({"notJson": "not valid json"}, f"{entry}/failed_checks") == [
        {"result": ["solo.check.under_test"]}
    ]


def test_undefined_evidence_does_not_flip_under_negation(tmp_path):
    """The CEL counterpart of Rego's ``not <undefined>`` trap, which *is*
    true and would pass. Here the error propagates through ``!`` rather than
    being negated, so an unparseable operand cannot turn a check into a pass
    — the only direction that would matter."""
    policy = CelPolicy(
        _write_check(tmp_path, '!(parse_json(input.notJson) == "x")'),
        functions=default_cel_functions(),
    )
    assert policy.query(
        {"notJson": "not valid json"}, "policybundle.examples.nonbool/allow"
    ) == [{"result": False}]


def test_native_cel_error_is_still_a_fault(tmp_path):
    """The carve-out is the ``undefined_evidence`` subclass only. A *native*
    ``CELEvalError`` — here an absent key with no ``has()`` guard — remains a
    fault, so the guard discipline the module docstring relies on is intact.
    Paired with :func:`test_parse_json_malformed_denies_without_aborting`:
    same engine, same shape of failure, deliberately different verdicts."""
    policy = CelPolicy(_write_check(tmp_path, 'input.missing.field == "x"'))
    with pytest.raises(PolicyEvaluationError):
        policy.query({}, "policybundle.examples.nonbool/allow")


def _write_check(tmp_path: Path, expr: str) -> Path:
    d = tmp_path / "nonbool"
    d.mkdir()
    (d / "checks.cel.json").write_text(json.dumps({
        "engine": "cel-v1",
        "package": "policybundle.examples.nonbool",
        "tiers": [{"tier": 0, "checks": ["solo.check.under_test"]}],
        "checks": {"solo.check.under_test": expr},
    }))
    return d / "checks.cel.json"


@pytest.mark.parametrize(
    "expr",
    [
        'input.merchant',            # a string: truthy, so always passed
        'input.approval',            # a map
        '[input.merchant]',          # a list
        '1',                         # an int
    ],
)
def test_non_boolean_check_fails_closed(tmp_path, expr):
    """A check is a predicate. bool() read a non-empty string, map or list as
    a pass, so a check that returned the thing it meant to compare passed
    unconditionally -- silently, and only in the direction that allows."""
    policy = CelPolicy(_write_check(tmp_path, expr))
    with pytest.raises(PolicyEvaluationError, match="not a boolean"):
        policy.query(
            {"merchant": "acme", "approval": {"amountCents": 500}},
            "policybundle.examples.nonbool/allow",
        )


def test_boolean_check_still_evaluates(tmp_path):
    policy = CelPolicy(_write_check(tmp_path, 'input.merchant == "acme"'))
    assert policy.query({"merchant": "acme"}, "policybundle.examples.nonbool/allow") == [
        {"result": True}
    ]

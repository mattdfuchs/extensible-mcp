# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The expression shapes under which an *undefined* operand becomes a pass,
pinned on both engines (#35).

Over-inclusion fails open, so this is the direction that matters: a shape
that turns garbage into ``true`` defeats a check without any bundle author
noticing. No adopted bundle contains one of these shapes on its ``allow``
side -- but nothing stops the next one, and a differential over the adopted
bundles cannot catch what those bundles do not contain. So the shapes are
enumerated here, each measured on each engine, with the fail-open set stated
as an explicit list that a new passing shape has to be added to by hand.

What the proxy can and cannot do about them. The Rego engine loads compiled
wasm, not source, so it cannot refuse ``not <rule>`` on the allow side at
load; that refusal belongs in the grammar of whatever emits the policy. The
CEL engine *could* reject ``||``, but ``||`` is legitimate; what makes the
row reachable is that the parsing builtins return error values rather than
raising (PR #33), and cel-python absorbs an error value in ``||`` from either
side. The test therefore pins behaviour rather than preventing it.

The undefined operand: in Rego, ``format_int(n, 7)`` -- base 7 is not one of
OPA's supported bases, so the call is undefined, not an error, exactly as
``json.unmarshal`` on non-JSON is. In CEL, ``parse_json("not json")`` -- which
returns the ``UndefinedEvidence`` error value, CEL's spelling of the same
thing. Both are "evidence a parsing builtin cannot parse", which is the
LLM-supplied case the manifest cannot screen.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from extensible_mcp.cel_policy import CelPolicy
from extensible_mcp.wasm_policy import OpaWasmPolicy, PolicyEvaluationError

REGO_FIXTURE = Path(__file__).parent / "fixtures" / "undefined_shapes" / "policy.wasm"
REGO_PKG = "policybundle/examples/undefined_shapes"
CEL_PKG = "policybundle.examples.undefined_shapes"

UNDEFINED_INPUT = {"n": 5, "base": 7, "ns": [1, 2, 3]}   # base 7: format_int undefined
DEFINED_INPUT = {"n": 5, "base": 10, "ns": [1, 2, 3]}    # the control
GARBAGE_INPUT = {"garbage": "not json"}                   # parse_json undefined

PASS, DENY, FAULT = "pass", "deny", "fault"

# entrypoint -> verdict on the undefined input. The comment is the shape; the
# fixture's PROVENANCE.md has the full table with the control column.
REGO_SHAPES = {
    "not_undefined_rule": PASS,        # not <partial rule, body undefined>
    "not_undefined_function": PASS,    # not <partial function call, body undefined>
    "count_comprehension_zero": PASS,  # count([..undefined legs..]) == 0
    "positive": DENY,                  # <undefined> == "5"
    "every_undefined": DENY,           # every n in ns { <undefined> }
    "max_undefined": DENY,             # max([..undefined..])
    "not_builtin_hoisted": DENY,       # not format_int(..) == "5": call hoisted out of `not`
}

# name -> (expression, verdict on the garbage input)
CEL_SHAPES = {
    "or_true_right": ('parse_json(input.garbage).f == "x" || true', PASS),
    "or_true_left": ('true || parse_json(input.garbage).f == "x"', PASS),
    "baseline_positive": ('parse_json(input.garbage).f == "x"', DENY),
    "and_false_left": ('false && parse_json(input.garbage).f == "x"', DENY),
    "and_true_right": ('parse_json(input.garbage).f == "x" && true', DENY),
    "negated": ('!(parse_json(input.garbage).f == "x")', DENY),
    "has_on_undefined": ('has(parse_json(input.garbage).f)', DENY),
    "in_list": ('parse_json(input.garbage).f in ["x"]', DENY),
    "not_in_list": ('!(parse_json(input.garbage).f in ["x"])', DENY),
    # Rego's count-over-comprehension has no CEL twin: the error value
    # propagates through the list literal and the filter, so the size
    # comparison is itself an error, not 0.
    "size_filter_zero": (
        'size([parse_json(input.garbage).f].filter(v, v != "ok")) == 0', DENY
    ),
    # A ternary whose condition is an error value is a *native* CELEvalError
    # ("no matching overload"), not UndefinedEvidence -- so it is a fault,
    # which fails closed but as an engine error rather than a denial.
    "ternary_cond": ('parse_json(input.garbage).f == "x" ? true : false', FAULT),
}

# The fail-open shapes, stated once, by hand. A shape that starts passing has
# to be added here on purpose -- see test_fail_open_shapes_are_exactly_these.
FAIL_OPEN = {
    "rego": {"not_undefined_rule", "not_undefined_function", "count_comprehension_zero"},
    "cel": {"or_true_right", "or_true_left"},
}


@pytest.fixture(scope="module")
def rego():
    return OpaWasmPolicy(REGO_FIXTURE)


def _rego_verdict(result) -> str:
    # [] is undefined; a defined boolean rule is [{"result": bool}].
    if not result:
        return DENY
    return PASS if result[0].get("result") is True else DENY


def _cel_policy(tmp_path: Path, name: str, expr: str) -> CelPolicy:
    d = tmp_path / name
    d.mkdir()
    (d / "checks.cel.json").write_text(json.dumps({
        "engine": "cel-v1",
        "package": CEL_PKG,
        "tiers": [{"tier": 0, "checks": [f"t0.{name}"]}],
        "checks": {f"t0.{name}": expr},
    }))
    return CelPolicy(d / "checks.cel.json")


def _cel_verdict(policy: CelPolicy, input_obj) -> str:
    try:
        allow = policy.query(input_obj, f"{CEL_PKG}/allow")
    except PolicyEvaluationError:
        return FAULT
    return PASS if allow == [{"result": True}] else DENY


@pytest.mark.parametrize("name", list(REGO_SHAPES))
def test_rego_shape_under_undefined(rego, name):
    """Each shape's verdict on an undefined operand is the one measured, and
    the control input shows the operand is the cause: on a defined operand
    the three fail-open shapes are *not* true (their helper is defined, the
    comprehension is non-empty) and the positive check is."""
    assert _rego_verdict(rego.query(UNDEFINED_INPUT, f"{REGO_PKG}/{name}")) == REGO_SHAPES[name]
    control = _rego_verdict(rego.query(DEFINED_INPUT, f"{REGO_PKG}/{name}"))
    if name in FAIL_OPEN["rego"]:
        assert control == DENY, "the pass came from the undefined operand, not the shape"
    if name == "positive":
        assert control == PASS


def test_rego_reason_side_uses_the_same_idiom_correctly(rego):
    """``not allow; not <helper>`` is how the generated bundles report a
    reason, and it relies on exactly ``not <undefined>`` being true. That is
    correct there -- it is how a reason gets reported at all. The hazard is
    the same shape on the ``allow`` side, which ``default allow := false``
    plus a positively-authored check keeps closed."""
    assert rego.query(UNDEFINED_INPUT, f"{REGO_PKG}/allow") == [{"result": False}]
    assert rego.query(UNDEFINED_INPUT, f"{REGO_PKG}/failed_checks") == [{"result": ["the_check"]}]
    assert rego.query(DEFINED_INPUT, f"{REGO_PKG}/allow") == [{"result": True}]
    assert rego.query(DEFINED_INPUT, f"{REGO_PKG}/failed_checks") == [{"result": []}]


@pytest.mark.parametrize("name", list(CEL_SHAPES))
def test_cel_shape_under_undefined(tmp_path, name):
    """cel-python absorbs an error value into ``||`` from either side --
    absorption is commutative in both logical operators -- and propagates it
    through everything else. ``&&`` toward ``false`` is the safe direction."""
    expr, expected = CEL_SHAPES[name]
    assert _cel_verdict(_cel_policy(tmp_path, name, expr), GARBAGE_INPUT) == expected


def test_fail_open_shapes_are_exactly_these():
    """The tables above are the differential's coverage of this question; the
    passing rows are the hazard, listed once by hand. A new shape that passes
    under an undefined operand fails here until someone adds it to
    ``FAIL_OPEN`` on purpose -- which is the review this test exists to
    force, since over-inclusion is the direction that fails open."""
    assert {n for n, v in REGO_SHAPES.items() if v == PASS} == FAIL_OPEN["rego"]
    assert {n for n, (_, v) in CEL_SHAPES.items() if v == PASS} == FAIL_OPEN["cel"]
    # And nothing on the safe side is a silent pass on either engine.
    assert not any(v == PASS for n, v in REGO_SHAPES.items() if n not in FAIL_OPEN["rego"])
    assert not any(v == PASS for n, (_, v) in CEL_SHAPES.items() if n not in FAIL_OPEN["cel"])

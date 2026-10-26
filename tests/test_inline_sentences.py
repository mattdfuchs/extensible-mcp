# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Denial text written beside the rule, for a bundle that ships no guidance.json.

A hand author puts the sentence next to the condition: a CEL check as
``{"expr", "sentence"}``, a Cedar ``@sentence`` annotation on the ``@id``
forbid, a Rego ``deny_reason`` rule. The loader synthesises the guidance the
renderer needs from the first two, and the proxy already falls back to the
third. These tests copy each teaching twin to a directory *without*
``guidance.json`` and hold the rendered denial to the one the guidance
renders -- byte for byte for CEL and Cedar, the English fallback for Rego --
then pin the defaults, the refusals, and that a shipped guidance.json wins.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.cedar_policy import CedarPolicy, CedarPolicyError
from extensible_mcp.cel_policy import CelPolicy
from extensible_mcp.policy_engine import inline_guidance
from extensible_mcp.types import CallRequest
from extensible_mcp.wasm_filter import WasmPolicyFilter
from tests.test_minimal_bundle_differential import (
    BUNDLES,
    FIXTURES,
    SCENARIOS,
    _config,
    _evidence,
)

SENTENCES = {
    "solo.request_vc.signed_by": "a credential signature is invalid",
    "solo.request_vc.within_window": "a credential is outside its validity window",
    "solo.request_vc.action_matches": "required: input.requestVC.claims.action == input.tool",
    "solo.request_vc.arguments_matches": "required: input.requestVC.claims.arguments == input.arguments",
    "solo.arguments.amount_cents_at_most": "required: input.arguments.amountCents <= 1000",
}
BARE = "Tool call denied by policy."


def _without_guidance(tmp_path: Path, engine: str, *, edit=None) -> Path:
    """A copy of the twin with guidance.json removed, and ``edit`` applied to it."""
    src = FIXTURES / BUNDLES[engine]
    dst = tmp_path / BUNDLES[engine]
    shutil.copytree(src, dst)
    (dst / "guidance.json").unlink()
    if edit is not None:
        edit(dst)
    return dst


async def _deny(bundle: PolicyBundle, key, stranger, scenario: str) -> str:
    s = SCENARIOS[scenario]
    args, req = _evidence(key, stranger, s)
    f = WasmPolicyFilter(bundle, config=_config(key), clock=lambda: s.now)
    result = await f.check(CallRequest(tool_name=s.tool, arguments={**args, "requestVC": req},
                                       server_name="payments"))
    assert not result.allowed
    return result.reason


@pytest.fixture(scope="module")
def key():
    from tests import vc_helpers as vc
    return vc.new_key()


@pytest.fixture(scope="module")
def stranger():
    from tests import vc_helpers as vc
    return vc.new_key()


# -- the inline text renders exactly what the guidance file renders ----------- #


@pytest.mark.parametrize("scenario", ["over_the_cap", "tampered_signature"])
@pytest.mark.parametrize("engine", ["cel", "cedar"])
async def test_without_guidance_the_inline_sentences_render_the_same_denial(
    tmp_path, key, stranger, engine, scenario
):
    with_guidance = PolicyBundle.load(FIXTURES / BUNDLES[engine])
    without = PolicyBundle.load(_without_guidance(tmp_path, engine))
    assert without.guidance["synthesized_from"] == "inline"
    expected = await _deny(with_guidance, key, stranger, scenario)
    assert expected != BARE and expected.startswith("Tool call denied by policy: no allowed path")
    assert await _deny(without, key, stranger, scenario) == expected


@pytest.mark.parametrize("scenario, sentence", [
    ("over_the_cap", SENTENCES["solo.arguments.amount_cents_at_most"]),
    ("tampered_signature", SENTENCES["solo.request_vc.signed_by"]),
])
async def test_rego_without_guidance_falls_back_to_its_deny_reason_rules(
    tmp_path, key, stranger, scenario, sentence
):
    """Rego's inline form is deny_reason, which the filter already honours as
    the fallback: the flat join of the fired sentences."""
    bundle = PolicyBundle.load(_without_guidance(tmp_path, "rego"))
    assert bundle.guidance is None and bundle.has_deny_reason()
    assert await _deny(bundle, key, stranger, scenario) == f"Tool call denied by policy: {sentence}."


def test_the_synthesized_guidance_carries_the_fetch_plans_call_guards(tmp_path):
    bundle = PolicyBundle.load(_without_guidance(tmp_path, "cel"))
    plan = json.loads((FIXTURES / BUNDLES["cel"] / "fetchplan.json").read_text())
    expected = [{"field": e["field"], **e["guard"]} for e in plan["entries"]
                if e["source"]["kind"] == "call"]
    assert bundle.guidance["call_guards"] == expected
    assert [c["id"] for t in bundle.guidance["tiers"] for c in t["checks"]] == list(SENTENCES)
    assert {c["id"]: c["sentence"] for t in bundle.guidance["tiers"] for c in t["checks"]} == SENTENCES


# -- a check with no sentence still renders something specific ---------------- #


async def test_cel_with_no_sentences_and_no_guidance_renders_the_expression(
    tmp_path, key, stranger
):
    def strip(d: Path) -> None:
        spec = json.loads((d / "checks.cel.json").read_text())
        spec["checks"] = {cid: v["expr"] for cid, v in spec["checks"].items()}
        (d / "checks.cel.json").write_text(json.dumps(spec))

    bundle = PolicyBundle.load(_without_guidance(tmp_path, "cel", edit=strip))
    assert bundle.policy.inline_sentences == {}
    reason = await _deny(bundle, key, stranger, "over_the_cap")
    assert "- Path 1: required: input.arguments.amountCents <= 1000." in reason
    reason = await _deny(bundle, key, stranger, "tampered_signature")
    assert "- Path 1: required: verify_eddsa(input.requestVC.jws, input.requesterJwk)." in reason


async def test_cedar_with_no_sentences_and_no_guidance_renders_the_id(tmp_path, key, stranger):
    def strip(d: Path) -> None:
        p = d / "policy.cedar"
        p.write_text(re.sub(r'@sentence\("[^"]*"\)\n', "", p.read_text()))

    bundle = PolicyBundle.load(_without_guidance(tmp_path, "cedar", edit=strip))
    assert bundle.policy.inline_sentences == {}
    reason = await _deny(bundle, key, stranger, "over_the_cap")
    assert "- Path 1: required: solo.arguments.amount_cents_at_most." in reason


def test_cedar_tiers_come_from_expected_ids_in_order():
    """The compact two-tier policy carries no @sentence; its synthesised
    guidance still has both paths, numbered by position, each with the ids
    expected_ids.json gives that tier."""
    policy = PolicyBundle.load(FIXTURES / "cedar_family_spend_compact").policy
    expected = json.loads((FIXTURES / "cedar_family_spend_compact" / "expected_ids.json").read_text())
    tiers = policy.inline_guidance()["tiers"]
    assert [t["tier"] for t in tiers] == [0, 1]
    assert [[c["id"] for c in t["checks"]] for t in tiers] == [t["ids"] for t in expected["tiers"]]
    assert all(c["sentence"] == "required: " + c["id"] for t in tiers for c in t["checks"])


# -- a shipped guidance.json wins ---------------------------------------------- #


async def test_guidance_json_wins_over_a_differing_inline_sentence(tmp_path, key, stranger):
    dst = tmp_path / "cel_minimal_spend"
    shutil.copytree(FIXTURES / BUNDLES["cel"], dst)
    spec = json.loads((dst / "checks.cel.json").read_text())
    spec["checks"]["solo.arguments.amount_cents_at_most"]["sentence"] = "an inline sentence nobody should see"
    (dst / "checks.cel.json").write_text(json.dumps(spec))
    bundle = PolicyBundle.load(dst)
    assert "synthesized_from" not in bundle.guidance
    reason = await _deny(bundle, key, stranger, "over_the_cap")
    assert "nobody should see" not in reason
    assert "- Path 1: required: input.arguments.amountCents <= 1000." in reason


# -- the hook, and what is refused --------------------------------------------- #


def test_the_hook_is_optional_for_an_engine_that_lacks_it():
    class Bare:
        def entrypoints(self): return []
        def query(self, i, e): return []
    assert inline_guidance(Bare()) is None
    assert inline_guidance(PolicyBundle.load(FIXTURES / BUNDLES["rego"]).policy) is None


def _cel(tmp_path: Path, value) -> Path:
    spec = json.loads((FIXTURES / BUNDLES["cel"] / "checks.cel.json").read_text())
    spec["checks"]["solo.arguments.amount_cents_at_most"] = value
    p = tmp_path / "checks.cel.json"
    p.write_text(json.dumps(spec))
    return p


@pytest.mark.parametrize("value, message", [
    ({"expr": "input.arguments.amountCents <= 1000", "sentance": "typo"}, r"unknown key\(s\) \['sentance'\]"),
    ({"sentence": "no expression"}, r"'expr' must be a non-empty CEL expression"),
    ({"expr": "input.arguments.amountCents <= 1000", "sentence": 7}, r"'sentence' must be a non-empty string"),
    ({"expr": "input.arguments.amountCents <= 1000", "sentence": ""}, r"'sentence' must be a non-empty string"),
    (["input.arguments.amountCents <= 1000"], r"must be a CEL expression string or an object"),
])
def test_cel_refuses_a_malformed_check_value(tmp_path, value, message):
    with pytest.raises(ValueError, match=message):
        CelPolicy(_cel(tmp_path, value))


def _cedar(tmp_path: Path, edit) -> Path:
    dst = tmp_path / "cedar_minimal_spend"
    shutil.copytree(FIXTURES / BUNDLES["cedar"], dst)
    p = dst / "policy.cedar"
    p.write_text(edit(p.read_text()))
    return p


def test_cedar_refuses_sentence_on_a_permit(tmp_path):
    p = _cedar(tmp_path, lambda t: t.replace('@tier("solo")\npermit', '@tier("solo")\n@sentence("x")\npermit', 1))
    with pytest.raises(CedarPolicyError, match=r"@sentence on a permit"):
        CedarPolicy(p)


def test_cedar_refuses_sentence_on_an_assembly_forbid(tmp_path):
    p = _cedar(tmp_path, lambda t: t.replace('@assembly("solo")\nforbid', '@assembly("solo")\n@sentence("x")\nforbid', 1))
    with pytest.raises(CedarPolicyError, match=r"@sentence on an @assembly forbid"):
        CedarPolicy(p)


def test_cedar_refuses_an_empty_sentence(tmp_path):
    p = _cedar(tmp_path, lambda t: t.replace(
        '@sentence("required: input.arguments.amountCents <= 1000")', '@sentence("")', 1))
    with pytest.raises(CedarPolicyError, match=r"empty @sentence"):
        CedarPolicy(p)

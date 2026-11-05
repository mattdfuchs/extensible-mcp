# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests for PolicyBundle's view of the fetch plan: the call-field partition,
the guards and the per-field schemas -- and that none of them consult an
entry's ``emit`` flag, which says whether a field reaches the assembled
input, never where it came from."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.fetchplan import DerivePlanError, FetchContext, FetchExecutor
from tests import vc_helpers as vc

FIXTURES = Path(__file__).parent / "fixtures"
MINIMAL_SPEND = FIXTURES / "minimal_spend"
CEDAR_MINIMAL_SPEND = FIXTURES / "cedar_minimal_spend"
SHIPPED_PLANS = sorted(FIXTURES.glob("*/fetchplan.json"))


def _set_emit(field, value):
    def mutate(plan):
        for e in plan["entries"]:
            if e["field"] == field:
                e["emit"] = value
    return mutate


def _add_entry(entry):
    def mutate(plan):
        plan["entries"].append(entry)
    return mutate


def _drop_property(field):
    def mutate(manifest):
        manifest["properties"].pop(field)
        manifest["required"].remove(field)
    return mutate


@pytest.fixture(scope="module")
def key():
    return vc.new_key()


def test_no_shipped_fixture_sets_emit():
    """Every plan in the corpus predates the flag and is silent about it, so
    the corpus exercises the default, and ``emit: true`` is exactly what the
    format has always meant."""
    assert SHIPPED_PLANS, "no fixture plans found"
    for path in SHIPPED_PLANS:
        for entry in json.loads(path.read_text())["entries"]:
            assert "emit" not in entry, f"{path}: {entry['field']}"


def test_the_credential_partition_is_independent_of_emit(rewritten_bundle):
    """Hazard 1, at the bundle: ``requestVC`` with ``emit: false`` is still a
    ``call`` field the LLM supplies, so it is still a credential field, still
    always required, guarded exactly as before. The manifest drops the
    property too, as an unemitted field's manifest must (see the load
    refusal below)."""
    shipped = PolicyBundle.load(MINIMAL_SPEND)
    bundle = PolicyBundle.load(
        rewritten_bundle(
            MINIMAL_SPEND,
            plan=_set_emit("requestVC", False),
            manifest=_drop_property("requestVC"),
        )
    )
    assert bundle.call_fields() == shipped.call_fields()
    assert bundle.credential_fields() == shipped.credential_fields() == ["requestVC"]
    assert bundle.is_always_required("requestVC") is True
    assert bundle.field_guard("requestVC") == shipped.field_guard("requestVC")


def test_field_schema_resolves_an_unemitted_entry_through_the_kept_definition(rewritten_bundle):
    """Hazard 2, at the bundle: the manifest drops the property and keeps the
    definition, and the entry's own ``$ref`` still resolves into it."""
    d = rewritten_bundle(
        MINIMAL_SPEND,
        plan=_set_emit("requestVC", False),
        manifest=_drop_property("requestVC"),
    )
    bundle = PolicyBundle.load(d)
    assert "requestVC" not in bundle.manifest["properties"]
    assert bundle.field_schema("requestVC") == bundle.definition("RequestVC")
    assert bundle.field_schema("requestVC")["properties"].keys() == {"jws", "claims"}


async def test_an_unemitted_field_passes_the_closed_manifest(rewritten_bundle, key):
    """The point of the flag: a field the manifest does not list is resolved,
    readable, and never offered to ``additionalProperties: false``. The same
    entry emitted is rejected, which is the regression direction."""
    extra = {"field": "requesterDid", "source": {"kind": "config"}, "emit": False}
    args = {"amountCents": 500, "merchant": "acme"}
    ctx = FetchContext(
        envelope={"tool": "send", "arguments": args,
                  "requestVC": vc.request_vc(args=args, key=key)},
        config={"requesterJwk": vc.public_jwk(key), "requesterDid": vc.KID_DID},
        now=100,
    )

    unemitted = PolicyBundle.load(rewritten_bundle(MINIMAL_SPEND, plan=_add_entry(extra)))
    assembled = await FetchExecutor().assemble(unemitted.fetchplan, ctx)
    assert "requesterDid" not in assembled
    assert unemitted.validate_input(assembled) == []

    emitted = PolicyBundle.load(
        rewritten_bundle(MINIMAL_SPEND, plan=_add_entry({**extra, "emit": True}))
    )
    assembled = await FetchExecutor().assemble(emitted.fetchplan, ctx)
    assert assembled["requesterDid"] == vc.KID_DID
    errors = emitted.validate_input(assembled)
    assert errors and "requesterDid" in errors[0], errors


@pytest.mark.parametrize("value", ["false", 0, None])
def test_load_refuses_a_non_boolean_emit_naming_the_field(rewritten_bundle, value):
    d = rewritten_bundle(MINIMAL_SPEND, plan=_set_emit("requestVC", value))
    with pytest.raises(DerivePlanError, match=r"'requestVC'.*'emit' must be a boolean"):
        PolicyBundle.load(d)


def test_load_refuses_an_unemitted_field_the_manifest_still_requires(rewritten_bundle):
    """``emit: false`` on a field the manifest's root ``required`` lists is a
    bundle no input can satisfy: every call would fail validation with a
    message about a field the author meant to drop. It fails at load,
    naming the field and both ways out, not on the first call."""
    d = rewritten_bundle(MINIMAL_SPEND, plan=_set_emit("requestVC", False))
    with pytest.raises(ValueError, match="'requestVC' carries 'emit': false") as e:
        PolicyBundle.load(d)
    assert "required" in str(e.value) and "or emit it" in str(e.value)


def test_a_cedar_bundle_accepts_the_flag_at_load(rewritten_bundle):
    """The Cedar branch checks plan entries on its own path
    (``refuse_reserved_plan_fields``); it accepts ``emit`` as the others do
    and refuses a malformed one the same way."""
    extra = {"field": "requesterDid", "source": {"kind": "config"}, "emit": False}
    bundle = PolicyBundle.load(
        rewritten_bundle(CEDAR_MINIMAL_SPEND, plan=_add_entry(extra))
    )
    assert bundle.credential_fields() == ["requestVC"]
    with pytest.raises(DerivePlanError, match=r"'requesterDid'.*'emit' must be a boolean"):
        PolicyBundle.load(
            rewritten_bundle(CEDAR_MINIMAL_SPEND, plan=_add_entry({**extra, "emit": "no"}))
        )


# --------------------------------------------------------------------------- #
# A wallet lookup is never keyed on what the model typed.
# --------------------------------------------------------------------------- #

FAMILY_SPEND = FIXTURES / "family_spend"


def _wallet_subject(field, subject):
    def mutate(plan):
        for e in plan["entries"]:
            if e["field"] == field:
                e["source"]["params"]["subject"] = subject
    return mutate


def test_every_shipped_wallet_lookup_is_keyed_inside_a_credential():
    """The invariant the loader now holds was an authoring convention first:
    every wallet subject in the corpus roots at a credential field."""
    from extensible_mcp.fetchplan import validate_wallet_subjects

    found = 0
    for path in SHIPPED_PLANS:
        plan = json.loads(path.read_text())
        validate_wallet_subjects(plan)
        for e in plan["entries"]:
            if e["source"].get("kind") == "wallet":
                found += 1
                root = e["source"]["params"]["subject"]["$input"].split(".")[0]
                assert root not in ("tool", "arguments"), f"{path}: {e['field']}"
    assert found > 0


@pytest.mark.parametrize(
    "subject, needle",
    [
        ({"$input": "arguments.merchant"}, r"read from 'arguments'"),
        ({"$input": "tool"}, r"read from 'tool'"),
    ],
)
def test_load_refuses_a_wallet_subject_the_model_types(rewritten_bundle, subject, needle):
    """``get_payment_methods(user_email=<victim>)``: the lookup would fetch
    an authority's statement about whoever the model named. Unexpressible,
    not merely absent from the corpus."""
    d = rewritten_bundle(FAMILY_SPEND, plan=_wallet_subject("requesterMembership", subject))
    with pytest.raises(DerivePlanError, match=needle) as e:
        PolicyBundle.load(d)
    assert "requesterMembership" in str(e.value) and "requestVC.claims.iss" in str(e.value)


def test_load_refuses_a_wallet_subject_derived_from_the_arguments(rewritten_bundle):
    """Laundering the argument through a ``derive`` entry does not help: the
    taint follows the ``$input`` references."""
    laundered = {
        "field": "payeeDigest",
        "source": {"kind": "derive", "fn": "sha256", "args": [{"$input": "arguments.merchant"}]},
        "schema": {"type": "string"},
    }

    def mutate(plan):
        plan["primitives"] = {"sha256": {"class": "pure"}}
        entries = plan["entries"]
        at = next(i for i, e in enumerate(entries) if e["field"] == "requesterMembership")
        entries.insert(at, laundered)
        entries[at + 1]["source"]["params"]["subject"] = {"$input": "payeeDigest"}

    with pytest.raises(DerivePlanError, match=r"'payeeDigest' \(derived from the call's own arguments\)"):
        PolicyBundle.load(rewritten_bundle(FAMILY_SPEND, plan=mutate))


def test_a_literal_wallet_subject_is_an_authors_constant(rewritten_bundle):
    bundle = PolicyBundle.load(
        rewritten_bundle(FAMILY_SPEND, plan=_wallet_subject("requesterMembership", "did:key:fixed"))
    )
    assert bundle.name == "family_spend"


# -- an integral float is not an integer -------------------------------------- #
#
# JSON Schema says a zero-fraction float satisfies {"type": "integer"}, and
# the engines then disagree on it: Rego decides, CEL has no overload across
# the two types, Cedar cannot build the request. The schema cannot express
# the exclusion, so the validator does, at the one seam every input crosses.


def _manifest_fixtures():
    from pathlib import Path

    root = Path(__file__).parent / "fixtures"
    return sorted(
        d.name for d in root.iterdir()
        if (d / "manifest.json").exists() and d.name != "classifier"
    )


@pytest.mark.parametrize("name", _manifest_fixtures())
def test_an_integral_float_fails_validation_at_its_path(name):
    import json
    from pathlib import Path

    from extensible_mcp.bundle import PolicyBundle
    from extensible_mcp.fetchplan import default_primitives
    from extensible_mcp.wasm_policy import default_builtins

    # The passkey fixtures declare verify_webauthn -- as a Rego builtin or a
    # Cedar derive primitive -- which the load refuses to leave unregistered;
    # the manifest under test is the same either way.
    builtins = default_builtins(webauthn_rp_id="wallet.example")
    primitives = default_primitives(webauthn_rp_id="wallet.example")
    bundle = PolicyBundle.load(Path(__file__).parent / "fixtures" / name, name=name,
                               builtins=builtins, primitives=primitives)
    for bad in (12.0, json.loads("1e3")):
        errors = bundle.validate_input({"now": bad})
        at_now = [e for e in errors if e.startswith("now:")]
        assert at_now and "integer" in at_now[0], (name, bad, errors)
    assert not [e for e in bundle.validate_input({"now": 12}) if e.startswith("now:")], name


def test_the_strict_integer_leaves_number_fields_and_bools_as_they_were():
    from jsonschema import Draft7Validator

    from extensible_mcp.bundle import _strict_integers

    number = _strict_integers(Draft7Validator)({"type": "number"})
    assert not list(number.iter_errors(12.0)) and not list(number.iter_errors(12))
    integer = _strict_integers(Draft7Validator)({"type": "integer"})
    assert not list(integer.iter_errors(12))
    assert list(integer.iter_errors(True)), "a bool is not an integer, as before"
    assert list(integer.iter_errors(12.0))

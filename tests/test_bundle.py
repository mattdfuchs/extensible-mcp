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
    always required, guarded exactly as before."""
    shipped = PolicyBundle.load(MINIMAL_SPEND)
    bundle = PolicyBundle.load(
        rewritten_bundle(MINIMAL_SPEND, plan=_set_emit("requestVC", False))
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

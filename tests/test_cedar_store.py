# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The Cedar entity store (#93): formed per call from the plan's ``entities``
block, validated against the bundle's ``schema.json`` at load, with ``in``
held to the relations the schema declares.

Four things are pinned here, each against the measurement that makes it
load-bearing:

1. **The block is read exactly.** A placement the loader cannot form as
   declared is refused at load, by name -- never half-read.
2. **The store is the block's projection of the input.** Placed fields leave
   ``context``; references are wrapped by the block, never by inspecting a
   value's shape (measured: without the wrap Cedar reads the record as a
   record and the owner is denied); membership fields become parents (Cedar
   closes them, so a grandparent is ``in``); a store that cannot be formed is
   a fault, not a denial.
3. **The schema is a hard gate, and the loader's own check sits beside it.**
   Cedar's validator refuses an undeclared attribute read with its own
   message -- and *passes* an ``in`` over a relation no ``memberOfTypes``
   declares (measured), typing it as ``false`` and reporting nothing. The
   loader refuses that one by name.
4. **Three bundles decide.** The two supplied loader-grammar fixtures
   (``cedar_approval``: attributes on the resource; ``cedar_channel``: entity
   references and the principal as a value) reproduce the supplier's
   scenario tables through this loader, and this repo's own
   ``cedar_family_hierarchy`` shows the three edge sources -- the IdP's
   roles claim, the deployment's config, a verified membership -- each
   deciding and each explained when absent.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.cedar_policy import CedarPolicy, CedarPolicyError
from extensible_mcp.cedar_store import (
    EntityPlacement,
    PlacementError,
    StoreFormationError,
    ancestor_types,
    check_placement_against_plan,
    form_store,
    member_of_graph,
    parse_placement,
)
from extensible_mcp.fetchplan import DerivePlanError, default_primitives, validate_derive_plan
from extensible_mcp.types import CallRequest, Principal
from extensible_mcp.wasm_filter import WasmPolicyFilter
from extensible_mcp.wasm_policy import PolicyEvaluationError
from tests import vc_helpers as vc

FIXTURES = Path(__file__).parent / "fixtures"
APPROVAL = FIXTURES / "cedar_approval"
CHANNEL = FIXTURES / "cedar_channel"
HIERARCHY = FIXTURES / "cedar_family_hierarchy"

PROBE = "!(context has probe)"

#: A small schema for the synthetic tests: a caller under roles (recursive),
#: a server under orgs, a document whose owner is a user.
SCHEMA = {"": {
    "entityTypes": {
        "Caller": {"memberOfTypes": ["Role"], "shape": {"type": "Record", "attributes": {}}},
        "Role": {"memberOfTypes": ["Role"], "shape": {"type": "Record", "attributes": {}}},
        "Server": {"memberOfTypes": ["Org"], "shape": {"type": "Record", "attributes": {
            "owner": {"type": "Entity", "name": "Caller"},
            "tags": {"type": "Set", "element": {"type": "String"}, "required": False}}}},
        "Org": {"shape": {"type": "Record", "attributes": {}}},
    },
    "actions": {"call": {"appliesTo": {
        "principalTypes": ["Caller"], "resourceTypes": ["Server"],
        "context": {"type": "Record", "attributes": {
            "probe": {"type": "Boolean", "required": False},
            "tool": {"type": "String", "required": False},
            "n": {"type": "Long", "required": False}}}}}},
}}

BLOCK = {
    "principal": {"type": "Caller", "id": {"from": "caller", "field": "sub"}, "attributes": []},
    "resource": {"type": "Server", "id": {"from": "package"}, "attributes": ["owner", "tags"]},
    "references": [{"field": "owner", "type": "Caller", "set": False}],
    "memberships": [{"field": "callerRoles", "of": "principal"},
                    {"field": "serverOrgs", "of": "resource"}],
}


def _permit(when: str, scope: str = "principal, action, resource") -> str:
    return (
        f'@tier("solo")\npermit ({scope}) when {{ {PROBE} && ({when}) }};\n'
        '@id("solo.never")\nforbid (principal, action, resource) '
        "when { context has probe && false };\n"
    )


def _engine(tmp_path: Path, policy: str, *, entities=None, schema=SCHEMA, package="pkg") -> CedarPolicy:
    (tmp_path / "policy.cedar").write_text(policy)
    if schema is not None:
        (tmp_path / "schema.json").write_text(json.dumps(schema))
    return CedarPolicy(tmp_path / "policy.cedar", package=package, entities=entities)


def _allows(engine: CedarPolicy, input_obj: dict) -> bool:
    (allow,) = (e for e in engine.entrypoints() if e.endswith("/allow"))
    return engine.query(input_obj, allow) == [{"result": True}]


def _ids(engine: CedarPolicy, input_obj: dict) -> set[str]:
    (failed,) = (e for e in engine.entrypoints() if e.endswith("/failed_checks"))
    return set(engine.query(input_obj, failed)[0]["result"])


# --------------------------------------------------------------------------- #
# 1. the block is read exactly
# --------------------------------------------------------------------------- #

class TestTheBlockIsRead:
    def test_no_block_is_the_default_placement(self):
        p = parse_placement(None, "plan")
        assert p == EntityPlacement.default() and not p.declared
        assert p.principal.type == "Caller" and p.resource.type == "Server"
        assert p.placed_fields() == frozenset()

    def test_the_supplied_blocks_round_trip(self):
        for fixture in (APPROVAL, CHANNEL, HIERARCHY):
            block = json.loads((fixture / "fetchplan.json").read_text())["entities"]
            p = parse_placement(block, "plan")
            assert p.declared
        channel = parse_placement(json.loads((CHANNEL / "fetchplan.json").read_text())["entities"], "plan")
        assert channel.principal.id_from == "input" and channel.principal.id_field == "principal"
        assert channel.placed_fields() == {"principal", "owner", "moderators"}
        assert channel.referenced_fields() == {"principal", "owner", "moderators"}

    @pytest.mark.parametrize("block, needle", [
        ({"principal": {"type": "Caller", "id": {"from": "caller", "field": "sub"}}, "extra": 1},
         "unknown key"),
        ({"resource": {"type": "ser ver", "id": {"from": "package"}}}, "entity type name"),
        ({"resource": {"type": "Server", "id": {"from": "caller", "field": "sub"}}}, "comes from one of"),
        ({"principal": {"type": "Caller", "id": {"from": "package"}}}, "comes from one of"),
        ({"resource": {"type": "Server", "id": {"from": "package", "field": "x"}}}, "takes no 'field'"),
        ({"resource": {"type": "Server", "id": {"from": "package"}, "attributes": ["a", "a"]}},
         "lists a field twice"),
        ({"principal": {"type": "Caller", "id": {"from": "caller", "field": "sub"}, "attributes": ["a"]},
          "resource": {"type": "Server", "id": {"from": "package"}, "attributes": ["a"]}},
         "placed twice"),
        ({"memberships": [{"field": "owners", "of": "owner"}]}, "attribute subject"),
        ({"references": [{"field": "r", "type": "Caller", "set": False}],
          "memberships": [{"field": "r", "of": "principal"}]}, "also listed under 'references'"),
        ({"nested": [{"field": "owner_blocked", "via": "owner", "as": "blocked"}]},
         "'references' does not list"),
        ({"references": [{"field": "viewers", "type": "Caller", "set": True}],
          "nested": [{"field": "x", "via": "viewers", "as": "blocked"}]}, "a set of references"),
        ({"principal": {"type": "User", "id": {"from": "input", "field": "principal"}}},
         "'references' must list as a single reference of type 'User'"),
        ({"principal": {"type": "User", "id": {"from": "input", "field": "principal"}},
          "references": [{"field": "principal", "type": "Group", "set": False}]},
         "single reference of type 'User'"),
    ])
    def test_a_malformed_block_is_refused_by_name(self, block, needle):
        with pytest.raises(PlacementError, match=needle):
            parse_placement(block, "plan")

    def test_a_malformed_block_refuses_the_bundle_at_load(self, tmp_path):
        with pytest.raises(CedarPolicyError, match="attribute subject"):
            _engine(tmp_path, _permit("true"), entities={"memberships": [{"field": "m", "of": "owner"}]})

    def test_a_placed_field_no_entry_assembles_is_refused(self):
        p = parse_placement(BLOCK, "plan")
        plan = {"entries": [{"field": f, "source": {"kind": "call"}} for f in ("owner", "callerRoles")]}
        with pytest.raises(PlacementError, match=r"\['serverOrgs', 'tags'\]"):
            check_placement_against_plan(p, plan, "plan")

    def test_an_unemitted_entry_does_not_count(self):
        p = parse_placement(BLOCK, "plan")
        plan = {"entries": [{"field": f, "source": {"kind": "call"}}
                            for f in ("owner", "tags", "callerRoles", "serverOrgs")]}
        check_placement_against_plan(p, plan, "plan")
        plan["entries"][1]["emit"] = False
        with pytest.raises(PlacementError, match=r"\['tags'\]"):
            check_placement_against_plan(p, plan, "plan")


# --------------------------------------------------------------------------- #
# 2. the store is the block's projection of the input
# --------------------------------------------------------------------------- #

class TestTheStoreIsFormed:
    P = parse_placement(BLOCK, "plan")

    def test_placed_fields_leave_context_and_absent_ones_stay_absent(self):
        formed = form_store({"caller": {"sub": "alice"}, "tags": ["a"], "n": 1}, self.P, "pkg")
        assert formed.head == {"principal": 'Caller::"alice"', "action": 'Action::"call"',
                               "resource": 'Server::"pkg"'}
        assert formed.context == {"caller": {"sub": "alice"}, "n": 1}
        by_type = {e["uid"]["type"]: e for e in formed.entities}
        assert by_type["Server"]["attrs"] == {"tags": ["a"]}  # owner absent: absent
        assert by_type["Caller"]["attrs"] == {} and by_type["Caller"]["parents"] == []

    def test_references_are_wrapped_by_the_block_not_by_shape(self):
        formed = form_store(
            {"owner": {"type": "Caller", "id": "bob"}, "n": {"type": "Caller", "id": "lookalike"}},
            self.P, "pkg",
        )
        server = next(e for e in formed.entities if e["uid"]["type"] == "Server")
        assert server["attrs"]["owner"] == {"__entity": {"type": "Caller", "id": "bob"}}
        # An unlisted field that happens to look like a reference is a record.
        assert formed.context["n"] == {"type": "Caller", "id": "lookalike"}

    def test_a_reference_of_another_type_cannot_form_the_store(self):
        with pytest.raises(StoreFormationError, match="references a 'Group', not the declared 'Caller'"):
            form_store({"owner": {"type": "Group", "id": "x"}}, self.P, "pkg")
        with pytest.raises(StoreFormationError, match="not an entity reference"):
            form_store({"owner": "bob"}, self.P, "pkg")

    def test_memberships_become_parents_and_absent_means_none(self):
        formed = form_store(
            {"caller": {"sub": "a"}, "callerRoles": [{"type": "Role", "id": "parent"}],
             "serverOrgs": [{"type": "Org", "id": "acme"}, {"type": "Org", "id": "umbrella"}]},
            self.P, "pkg",
        )
        by_type = {e["uid"]["type"]: e for e in formed.entities}
        assert by_type["Caller"]["parents"] == [{"type": "Role", "id": "parent"}]
        assert by_type["Server"]["parents"] == [{"type": "Org", "id": "acme"}, {"type": "Org", "id": "umbrella"}]
        assert "callerRoles" not in formed.context and "serverOrgs" not in formed.context
        assert form_store({}, self.P, "pkg").entities[0]["parents"] == []

    @pytest.mark.parametrize("value, needle", [
        ("acme", "not a list of entity references"),
        ([{"type": "Org"}], r"serverOrgs\[0\] is not an entity reference"),
        ([{"type": "Org", "id": 3}], r"serverOrgs\[0\] is not an entity reference"),
    ])
    def test_a_membership_field_that_is_not_references_cannot_form_the_store(self, value, needle):
        with pytest.raises(StoreFormationError, match=needle):
            form_store({"serverOrgs": value}, self.P, "pkg")

    def test_the_principal_from_an_input_field_leaves_context(self):
        p = parse_placement(json.loads((CHANNEL / "fetchplan.json").read_text())["entities"], "plan")
        formed = form_store(
            {"principal": {"type": "User", "id": "alice"}, "owner": {"type": "User", "id": "alice"},
             "moderators": [{"type": "User", "id": "bob"}]},
            p, "general",
        )
        assert formed.head["principal"] == 'User::"alice"' and "principal" not in formed.context
        channel = next(e for e in formed.entities if e["uid"]["type"] == "Channel")
        assert channel["attrs"]["moderators"] == [{"__entity": {"type": "User", "id": "bob"}}]
        with pytest.raises(StoreFormationError, match="id field 'principal' is absent"):
            form_store({"owner": {"type": "User", "id": "a"}, "moderators": []}, p, "general")
        with pytest.raises(StoreFormationError, match="references a 'Group', not the declared 'User'"):
            form_store({"principal": {"type": "Group", "id": "g"}, "moderators": []}, p, "general")

    def test_a_nested_attribute_lands_on_the_referenced_entity(self):
        block = {**BLOCK, "nested": [{"field": "owner_blocked", "via": "owner", "as": "blocked"}]}
        p = parse_placement(block, "plan")
        formed = form_store({"owner": {"type": "Caller", "id": "bob"}, "owner_blocked": True}, p, "pkg")
        bob = next(e for e in formed.entities if e["uid"] == {"type": "Caller", "id": "bob"})
        assert bob["attrs"] == {"blocked": True} and "owner_blocked" not in formed.context
        with pytest.raises(StoreFormationError, match="entity reference 'owner' is absent"):
            form_store({"owner_blocked": True}, p, "pkg")

    def test_the_same_entity_at_both_heads_is_one_entry(self):
        block = {"principal": {"type": "Thing", "id": {"from": "input", "field": "p"}, "attributes": ["a"]},
                 "resource": {"type": "Thing", "id": {"from": "input", "field": "r"}, "attributes": ["b"]},
                 "references": [{"field": "p", "type": "Thing", "set": False},
                                {"field": "r", "type": "Thing", "set": False}]}
        p = parse_placement(block, "plan")
        same = {"type": "Thing", "id": "x"}
        formed = form_store({"p": same, "r": same, "a": 1, "b": 2}, p, "pkg")
        assert formed.entities == [{"uid": same, "attrs": {"a": 1, "b": 2}, "parents": []}]

    def test_a_control_character_in_an_id_is_a_fault(self):
        with pytest.raises(PolicyEvaluationError, match="control character"):
            form_store({"callerRoles": [{"type": "Role", "id": "p\narent"}]}, self.P, "pkg")
        with pytest.raises(PolicyEvaluationError, match="control character"):
            form_store({"caller": {"sub": "a\x01"}}, self.P, "pkg")

    def test_the_default_placement_is_the_old_head(self):
        formed = form_store({"caller": {"sub": "alice", "roles": ["parent"]}, "tool": "send"},
                            EntityPlacement.default(), "family")
        assert formed.head == {"principal": 'Caller::"alice"', "action": 'Action::"send"',
                               "resource": 'Server::"family"'}
        assert formed.context == {"caller": {"sub": "alice", "roles": ["parent"]}, "tool": "send"}
        assert [e["uid"] for e in formed.entities] == [{"type": "Caller", "id": "alice"},
                                                       {"type": "Server", "id": "family"}]


# --------------------------------------------------------------------------- #
# 3. the schema gate, and the loader's own check beside it
# --------------------------------------------------------------------------- #

class TestTheSchemaGate:
    def test_a_bundle_with_a_schema_is_validated_and_may_test_in(self, tmp_path):
        engine = _engine(tmp_path, _permit('principal in Role::"parent"'), entities=BLOCK)
        assert engine.schema_validated
        assert _allows(engine, {"caller": {"sub": "a"}, "callerRoles": [{"type": "Role", "id": "parent"}]})
        assert not _allows(engine, {"caller": {"sub": "a"}, "callerRoles": [{"type": "Role", "id": "child"}]})
        assert not _allows(engine, {"caller": {"sub": "a"}})

    def test_the_validator_refuses_an_undeclared_attribute_with_its_own_message(self, tmp_path):
        with pytest.raises(CedarPolicyError, match=r"fails Cedar's validator.*attribute `zzz`"):
            _engine(tmp_path, _permit("principal.zzz == 1"), entities=BLOCK)

    def test_the_validator_refuses_a_type_error(self, tmp_path):
        with pytest.raises(CedarPolicyError, match="fails Cedar's validator"):
            _engine(tmp_path, _permit('context has n && context.n == "one"'), entities=BLOCK)

    @pytest.mark.parametrize("when", [
        'principal in Org::"acme"',                              # undeclared relation
        'principal is Caller in Org::"acme"',                    # the same, as `is … in`
        'resource has owner && resource.owner in Role::"r"',     # an attribute subject
        'action in Org::"acme"',                                 # an action group
    ])
    def test_cedar_itself_passes_these_in_a_when_clause(self, when):
        """The measurement that makes the loader's check load-bearing: in a
        `when` clause the validator types each of these as false and reports
        nothing (in the scope it does see an impossible relation)."""
        import cedarpy

        result = cedarpy.validate_policies(f"permit (principal, action, resource) when {{ {when} }};", SCHEMA)
        assert result.validation_passed and not list(result.errors)

    def test_an_in_over_an_undeclared_relation_is_refused_by_name(self, tmp_path):
        with pytest.raises(CedarPolicyError, match=r"tests a Caller against Org::…, a relation schema\.json does not declare"):
            _engine(tmp_path, _permit('principal in Org::"acme"'), entities=BLOCK)
        (tmp_path / "s").mkdir()
        with pytest.raises(CedarPolicyError, match="tests a Server against Role"):
            _engine(tmp_path / "s", _permit('resource in Role::"r"'), entities=BLOCK)
        # A heterogeneous set the validator refuses first, with its own message.
        (tmp_path / "h").mkdir()
        with pytest.raises(CedarPolicyError, match="fails Cedar's validator"):
            _engine(tmp_path / "h", _permit('resource in [Org::"a", Role::"r"]'), entities=BLOCK)

    def test_a_transitive_relation_is_declared(self, tmp_path):
        """Role memberOf Role: an ancestor's ancestor is reachable, and Cedar
        closes the edges, so a grandparent is `in`."""
        engine = _engine(tmp_path, _permit('principal in Role::"adult"'), entities=BLOCK)
        assert _allows(engine, {"callerRoles": [{"type": "Role", "id": "adult"}]})
        # The closure is the membership field's job; a store handed only the
        # direct parent does not know the grandparent, and that is correct:
        # the field *is* the closure.
        assert not _allows(engine, {"callerRoles": [{"type": "Role", "id": "parent"}]})

    def test_in_over_an_entity_typed_attribute_is_checked_against_the_schema(self, tmp_path):
        engine = _engine(tmp_path, _permit("resource has owner && principal in resource.owner"), entities=BLOCK)
        assert _allows(engine, {"caller": {"sub": "bob"}, "owner": {"type": "Caller", "id": "bob"}})
        assert not _allows(engine, {"caller": {"sub": "ann"}, "owner": {"type": "Caller", "id": "bob"}})
        # An attribute the schema types as a set of strings: the validator's
        # own refusal, since `in` wants an entity or a set of them.
        (tmp_path / "t").mkdir()
        with pytest.raises(CedarPolicyError, match="fails Cedar's validator"):
            _engine(tmp_path / "t", _permit("resource has tags && principal in resource.tags"), entities=BLOCK)

    def test_in_with_an_attribute_subject_or_the_action_is_refused(self, tmp_path):
        with pytest.raises(CedarPolicyError, match="attribute subject"):
            _engine(tmp_path, _permit('resource has owner && resource.owner in Role::"r"'), entities=BLOCK)
        # Both pass Cedar's validator (measured in the test above); the loader
        # refuses them because this release forms no hierarchy for either.
        (tmp_path / "a").mkdir()
        with pytest.raises(CedarPolicyError, match="action groups"):
            _engine(tmp_path / "a", _permit('action in Org::"acme"'), entities=BLOCK)

    def test_the_scope_is_checked_too(self, tmp_path):
        engine = _engine(tmp_path, _permit("true", scope='principal in Role::"parent", action, resource'), entities=BLOCK)
        assert _allows(engine, {"callerRoles": [{"type": "Role", "id": "parent"}]})
        # In the scope the validator sees the impossible relation itself
        # ("unable to find an applicable action"); in a `when` clause it does
        # not, which is the case the loader's check exists for.
        (tmp_path / "b").mkdir()
        with pytest.raises(CedarPolicyError, match="fails Cedar's validator"):
            _engine(tmp_path / "b", _permit("true", scope='principal in Org::"acme", action, resource'), entities=BLOCK)
        (tmp_path / "c").mkdir()
        with pytest.raises(CedarPolicyError, match="tests a Caller against Org"):
            _engine(tmp_path / "c", _permit('principal is Caller in Org::"acme"'), entities=BLOCK)

    def test_without_a_schema_in_is_still_refused(self, tmp_path):
        with pytest.raises(CedarPolicyError, match=r"ships no schema\.json"):
            _engine(tmp_path, _permit('principal in Role::"parent"'), entities=BLOCK, schema=None)

    def test_a_schema_that_is_not_one_is_refused(self, tmp_path):
        (tmp_path / "policy.cedar").write_text(_permit("true"))
        (tmp_path / "schema.json").write_text("[1]")
        with pytest.raises(CedarPolicyError, match="object of namespaces"):
            CedarPolicy(tmp_path / "policy.cedar", package="p")
        (tmp_path / "schema.json").write_text('{"": {"entityTypes": "no"}}')
        with pytest.raises(CedarPolicyError, match="not a schema Cedar can load"):
            CedarPolicy(tmp_path / "policy.cedar", package="p")

    def test_namespaced_types_resolve(self, tmp_path):
        schema = {"N": {
            "entityTypes": {"User": {"memberOfTypes": ["Team"], "shape": {"type": "Record", "attributes": {}}},
                            "Team": {"shape": {"type": "Record", "attributes": {}}},
                            "Doc": {"shape": {"type": "Record", "attributes": {}}}},
            "actions": {"call": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Doc"],
                                                "context": {"type": "Record", "attributes": {
                                                    "probe": {"type": "Boolean", "required": False}}}}}}}}
        graph = member_of_graph(schema)
        assert graph["N::User"] == {"N::Team"} and ancestor_types(graph, "N::User") == {"N::Team"}
        block = {"principal": {"type": "N::User", "id": {"from": "caller", "field": "sub"}},
                 "resource": {"type": "N::Doc", "id": {"from": "package"}},
                 "memberships": [{"field": "teams", "of": "principal"}]}
        engine = _engine(tmp_path, _permit('principal in N::Team::"core" && principal is N::User'),
                         entities=block, schema=schema)
        assert _allows(engine, {"caller": {"sub": "a"}, "teams": [{"type": "N::Team", "id": "core"}]})
        assert not _allows(engine, {"caller": {"sub": "a"}, "teams": []})


class TestTheMeasurementsBehindTheRules:
    def test_a_bare_record_is_not_an_entity_without_a_schema(self):
        """Why the loader writes the `__entity` escape by the block: Cedar's
        JSON reads a bare `{"type", "id"}` as a record unless a schema says
        otherwise, and the schema stays out of `is_authorized`."""
        import cedarpy

        policy = "permit (principal, action, resource) when { resource.owner == principal };"
        req = {"principal": 'Caller::"bob"', "action": 'Action::"call"', "resource": 'Server::"s"', "context": {}}
        bare = [{"uid": {"type": "Server", "id": "s"}, "attrs": {"owner": {"type": "Caller", "id": "bob"}}, "parents": []}]
        wrapped = [{"uid": {"type": "Server", "id": "s"}, "attrs": {"owner": {"__entity": {"type": "Caller", "id": "bob"}}}, "parents": []}]
        assert cedarpy.is_authorized(req, policy, bare).decision == cedarpy.Decision.Deny
        assert cedarpy.is_authorized(req, policy, wrapped).decision == cedarpy.Decision.Allow

    def test_cedar_closes_parent_edges_and_refuses_a_cycle(self, tmp_path):
        import cedarpy

        req = {"principal": 'Caller::"a"', "action": 'Action::"call"', "resource": 'Server::"s"', "context": {}}
        chain = [{"uid": {"type": "Caller", "id": "a"}, "attrs": {}, "parents": [{"type": "Role", "id": "p"}]},
                 {"uid": {"type": "Role", "id": "p"}, "attrs": {}, "parents": [{"type": "Role", "id": "gp"}]}]
        policy = 'permit (principal, action, resource) when { principal in Role::"gp" };'
        assert cedarpy.is_authorized(req, policy, chain).decision == cedarpy.Decision.Allow
        # A cycle is NoDecision with a diagnostic, which the engine treats as a
        # fault. A membership field is a closure and cannot carry one, so this
        # is the engine's floor, not a path a bundle reaches.
        cyc = [{"uid": {"type": "Role", "id": "a"}, "attrs": {}, "parents": [{"type": "Role", "id": "b"}]},
               {"uid": {"type": "Role", "id": "b"}, "attrs": {}, "parents": [{"type": "Role", "id": "a"}]}]
        assert cedarpy.is_authorized(req, policy, cyc).decision == cedarpy.Decision.NoDecision

    def test_the_old_hazard_the_refusal_closes_is_still_measurable(self):
        import cedarpy

        policy = ('permit (principal, action, resource);\n'
                  'forbid (principal in Group::"kids", action, resource) when { true };\n')
        req = {"principal": 'Caller::"anonymous"', "action": 'Action::"call"', "resource": 'Server::"g"', "context": {}}
        res = cedarpy.is_authorized(req, policy, [])
        assert res.decision == cedarpy.Decision.Allow and not list(res.diagnostics.errors)


# --------------------------------------------------------------------------- #
# 4. three bundles decide
# --------------------------------------------------------------------------- #

def _approval_doc(principal="a", status="in_review", required=("a", "b"), current=("a", "b")) -> dict:
    return {"principal": principal, "status": status,
            "requiredApprovers": list(required), "currentApprovals": list(current)}


APPROVAL_SCENARIOS = {
    "all approved": (_approval_doc(), True, set()),
    "approved in another order": (_approval_doc(current=("b", "a")), True, set()),
    "a superset of approvals": (_approval_doc(current=("c", "b", "a")), True, set()),
    "duplicates on both sides": (_approval_doc(required=("a", "a", "b"), current=("b", "b", "a")), True, set()),
    "one approver missing": (_approval_doc(current=("a",)), False, {"t0.required_approvers.all_match"}),
    "nobody has approved": (_approval_doc(current=()), False, {"t0.required_approvers.all_match"}),
    "principal is not a required approver": (_approval_doc(principal="z"), False, {"t0.required_approvers.has_a_match"}),
    "still a draft": (_approval_doc(status="draft"), False, {"t0.status.matches"}),
    "already approved (terminal)": (_approval_doc(status="approved"), False, {"t0.status.matches"}),
    "empty required set": (_approval_doc(required=(), current=()), False, {"t0.required_approvers.has_a_match"}),
    "everything wrong": (_approval_doc(principal="z", status="rejected", current=()), False,
                         {"t0.required_approvers.has_a_match", "t0.status.matches",
                          "t0.required_approvers.all_match"}),
}


class TestTheApprovalBundle:
    """The supplier's scenario table, through this loader: attributes placed
    on the resource read as `resource.<f>`."""

    @pytest.fixture(scope="class")
    def engine(self):
        return PolicyBundle.load(APPROVAL, name="cedar_approval").policy

    def test_it_loads_with_the_block_and_the_schema(self, engine):
        assert engine.schema_validated and engine.shape == "permit-decides"
        assert engine.placement.resource.type == "Document"
        assert engine.placement.resource.attributes == ("status", "requiredApprovers", "currentApprovals")
        assert engine.placement.placed_fields() == {"status", "requiredApprovers", "currentApprovals"}

    @pytest.mark.parametrize("name", sorted(APPROVAL_SCENARIOS))
    def test_the_suppliers_scenarios_decide_as_published(self, engine, name):
        doc, allowed, ids = APPROVAL_SCENARIOS[name]
        assert _allows(engine, doc) is allowed
        assert _ids(engine, doc) == ids

    async def test_through_the_filter(self):
        bundle = PolicyBundle.load(APPROVAL, name="cedar_approval")
        flt = WasmPolicyFilter(bundle, config={})
        ok = await flt.check(CallRequest(tool_name="docs__finalize", arguments=_approval_doc(), server_name="docs"))
        assert ok.allowed
        # The placed fields are credential fields to the filter: stripped downstream.
        assert ok.arguments == {}
        denied = await flt.check(CallRequest(tool_name="docs__finalize", arguments=_approval_doc(status="draft"),
                                             server_name="docs"))
        assert not denied.allowed and 'required: input.status == "in_review"' in denied.reason


def _channel_doc(principal="alice", owner="alice", moderators=("bob", "carol"), swapped=False) -> dict:
    ref = (lambda i: {"id": i, "type": "User"}) if swapped else (lambda i: {"type": "User", "id": i})
    return {"principal": ref(principal), "owner": ref(owner), "moderators": [ref(m) for m in moderators]}


CHANNEL_CHECK = "t0.principal.moderates"
CHANNEL_SCENARIOS = {
    "the owner": (_channel_doc(), True, set()),
    "a moderator": (_channel_doc(principal="carol"), True, set()),
    "the owner, who is also a moderator": (_channel_doc(principal="dan", owner="dan", moderators=("dan",)), True, set()),
    "a member who is neither": (_channel_doc(principal="zed"), False, {CHANNEL_CHECK}),
    "a stranger to an unmoderated channel": (_channel_doc(principal="zed", moderators=()), False, {CHANNEL_CHECK}),
    "the owner of an unmoderated channel": (_channel_doc(moderators=()), True, set()),
    "keys in the other order": (_channel_doc(swapped=True), True, set()),
    "a moderator, keys in the other order": (_channel_doc(principal="bob", swapped=True), True, set()),
}


class TestTheChannelBundle:
    """The supplier's scenario table, through this loader: entity references
    wrapped by the block, the principal formed from an input field."""

    @pytest.fixture(scope="class")
    def engine(self):
        return PolicyBundle.load(CHANNEL, name="cedar_channel").policy

    def test_it_loads_with_the_block_and_the_schema(self, engine):
        assert engine.schema_validated
        assert engine.placement.principal.id_from == "input"
        assert {r.field for r in engine.placement.references} == {"principal", "owner", "moderators"}

    @pytest.mark.parametrize("name", sorted(CHANNEL_SCENARIOS))
    def test_the_suppliers_scenarios_decide_as_published(self, engine, name):
        doc, allowed, ids = CHANNEL_SCENARIOS[name]
        assert _allows(engine, doc) is allowed
        assert _ids(engine, doc) == ids

    def test_a_missing_principal_is_a_fault_at_the_engine(self, engine):
        """Through the filter the manifest refuses it first; at the engine the
        declared store cannot be formed, which is a fault and never a quiet
        deny."""
        with pytest.raises(StoreFormationError, match="id field 'principal' is absent"):
            engine.query({"owner": {"type": "User", "id": "a"}, "moderators": []}, "cedar_channel/allow")

    def test_an_input_carrying_the_escape_itself_is_refused(self, engine):
        with pytest.raises(PolicyEvaluationError, match="__"):
            engine.query({**_channel_doc(), "owner": {"__entity": {"type": "User", "id": "alice"}}},
                         "cedar_channel/allow")

    async def test_through_the_filter(self):
        bundle = PolicyBundle.load(CHANNEL, name="cedar_channel")
        flt = WasmPolicyFilter(bundle, config={})
        ok = await flt.check(CallRequest(tool_name="chat__deleteMessage", arguments=_channel_doc(principal="bob"),
                                         server_name="chat"))
        assert ok.allowed
        denied = await flt.check(CallRequest(tool_name="chat__deleteMessage", arguments=_channel_doc(principal="zed"),
                                             server_name="chat"))
        assert not denied.allowed and "neither the channel's owner nor one of its moderators" in denied.reason
        # A reference of another type at a `User` field: the manifest's `const`
        # refuses it before any engine runs.
        off = await flt.check(CallRequest(tool_name="chat__deleteMessage",
                                          arguments={**_channel_doc(), "owner": {"type": "Group", "id": "g"}},
                                          server_name="chat"))
        assert not off.allowed and "manifest validation" in off.reason


class TestTheHierarchyBundle:
    """This repo's own: three edges, three sources, each deciding and each
    explained when absent."""

    SENTENCE = {
        "solo.caller.idp_role_parent": "the caller's identity provider does not assert the parent role",
        "solo.server.in_org": "this server is not in the organization the policy governs",
        "solo.caller.family_member": "the caller's membership credential is not signed by the household's trust root",
        "solo.membership.names_caller": "the membership credential names someone other than the caller",
        "solo.membership.within_window": "a credential is outside its validity window",
        "solo.arguments.amount_cents_at_most": "required: input.arguments.amountCents <= 5000",
    }

    @pytest.fixture(scope="class")
    def key(self):
        return vc.new_key()

    @pytest.fixture(scope="class")
    def stranger(self):
        return vc.new_key()

    @pytest.fixture(scope="class")
    def bundle(self):
        return PolicyBundle.load(HIERARCHY, name="cedar_family_hierarchy")

    @staticmethod
    def _filter(bundle, key, orgs=({"type": "Org", "id": "acme"},)):
        return WasmPolicyFilter(
            bundle, config={"trustRootJwk": vc.public_jwk(key), "serverOrgs": list(orgs)}, clock=lambda: 100,
        )

    @staticmethod
    def _call(key, *, sub="alice", roles=("parent",), amount=500, membership_sub=None, exp=9999999999,
              principal=True) -> CallRequest:
        m = vc.membership(sub=membership_sub or sub, role="parent", key=key)
        m["claims"]["exp"] = exp
        return CallRequest(
            tool_name="payments__send",
            arguments={"amountCents": amount, "merchant": "acme", "requesterMembership": m},
            server_name="payments",
            principal=Principal(sub=sub, iss="https://idp.example", roles=frozenset(roles)) if principal else None,
        )

    def test_it_loads_with_three_memberships_and_a_schema(self, bundle):
        p = bundle.policy
        assert p.schema_validated and p.shape == "permit-decides" and not p.expected_ids_declared
        assert [(m.field, m.of) for m in p.placement.memberships] == [
            ("callerIdpRoles", "principal"), ("callerFamilies", "principal"), ("serverOrgs", "resource")]
        assert set(p.expected_ids) == set(self.SENTENCE)

    async def test_every_edge_present_allows(self, bundle, key):
        result = await self._filter(bundle, key).check(self._call(key))
        assert result.allowed, result.reason
        assert "requesterMembership" not in result.arguments

    @pytest.mark.parametrize("name, check_id", [
        ("child role", "solo.caller.idp_role_parent"),
        ("other org", "solo.server.in_org"),
        ("stranger signed", "solo.caller.family_member"),
        ("names someone else", "solo.membership.names_caller"),
        ("expired", "solo.membership.within_window"),
        ("over cap", "solo.arguments.amount_cents_at_most"),
    ])
    async def test_each_absent_edge_or_failed_check_is_explained(self, bundle, key, stranger, name, check_id):
        flt = self._filter(bundle, key)
        call = self._call(key)
        if name == "child role":
            call = self._call(key, roles=("child",))
        elif name == "other org":
            flt = self._filter(bundle, key, orgs=({"type": "Org", "id": "other"},))
        elif name == "stranger signed":
            call = self._call(stranger)
        elif name == "names someone else":
            call = self._call(key, membership_sub="bob")
        elif name == "expired":
            call = self._call(key, exp=50)
        elif name == "over cap":
            call = self._call(key, amount=9000)
        result = await flt.check(call)
        assert not result.allowed
        assert self.SENTENCE[check_id] in result.reason
        # One condition failed: no other sentence is rendered.
        others = [s for cid, s in self.SENTENCE.items() if cid != check_id]
        assert not any(s in result.reason for s in others), result.reason

    async def test_two_absent_edges_render_both(self, bundle, key, stranger):
        result = await self._filter(bundle, key).check(self._call(stranger, roles=()))
        assert not result.allowed
        assert self.SENTENCE["solo.caller.idp_role_parent"] in result.reason
        assert self.SENTENCE["solo.caller.family_member"] in result.reason

    async def test_no_principal_fails_closed_before_the_store(self, bundle, key):
        result = await self._filter(bundle, key).check(self._call(key, principal=False))
        assert not result.allowed and "could not be assembled" in result.reason

    async def test_a_config_value_that_is_not_references_is_refused_by_the_manifest(self, bundle, key):
        result = await self._filter(bundle, key, orgs=("acme",)).check(self._call(key))
        assert not result.allowed and "manifest validation" in result.reason

    def test_at_the_engine_the_same_value_cannot_form_the_store(self, bundle):
        """The manifest is the first line; the block is the second, for an
        input that reached the engine without it (an embedder's own path).
        A fault, never a denial."""
        with pytest.raises(StoreFormationError, match="membership field 'serverOrgs' is not a list"):
            bundle.policy.query({"serverOrgs": "acme", "tool": "send"}, "cedar_family_hierarchy/allow")

    def test_an_in_over_a_relation_the_schema_lacks_is_refused_at_load(self, tmp_path):
        d = tmp_path / "cedar_family_hierarchy"
        shutil.copytree(HIERARCHY, d)
        policy = (d / "policy.cedar").read_text().replace('resource in Org::"acme"', 'resource in Family::"household"')
        (d / "policy.cedar").write_text(policy)
        with pytest.raises(CedarPolicyError, match="tests a Server against Family"):
            PolicyBundle.load(d, name="cedar_family_hierarchy")

    def test_without_the_schema_the_bundle_is_refused_for_its_in(self, tmp_path):
        d = tmp_path / "cedar_family_hierarchy"
        shutil.copytree(HIERARCHY, d)
        (d / "schema.json").unlink()
        with pytest.raises(CedarPolicyError, match=r"`in` is refused.*ships no schema\.json"):
            PolicyBundle.load(d, name="cedar_family_hierarchy")

    def test_the_inline_sentences_are_the_guidance_sentences(self, bundle):
        guidance = json.loads((HIERARCHY / "guidance.json").read_text())
        by_id = {c["id"]: c["sentence"] for t in guidance["tiers"] for c in t["checks"]}
        assert bundle.policy.inline_sentences == by_id == self.SENTENCE


# --------------------------------------------------------------------------- #
# the primitives that mint references
# --------------------------------------------------------------------------- #

class TestTheEntityReferencePrimitives:
    def test_entity_refs_turns_ids_into_references_in_order(self):
        prims = default_primitives()
        assert prims["entity_refs"]("IdpRole", ["parent", "admin"]) == [
            {"type": "IdpRole", "id": "parent"}, {"type": "IdpRole", "id": "admin"}]
        assert prims["entity_refs"]("IdpRole", []) == []
        assert prims["entity_ref"]("N::Org", "acme") == {"type": "N::Org", "id": "acme"}

    @pytest.mark.parametrize("call", [
        lambda p: p["entity_refs"]("IdpRole", "parent"),
        lambda p: p["entity_refs"]("IdpRole", [1]),
        lambda p: p["entity_ref"]("idp role", "x"),
        lambda p: p["entity_ref"]("IdpRole", None),
    ])
    def test_a_wrong_shape_is_a_fault_not_an_empty_set(self, call):
        from extensible_mcp.wasm_policy import HostBuiltinError

        with pytest.raises(HostBuiltinError):
            call(default_primitives())

    def test_the_type_must_be_a_plan_literal(self):
        plan = {"entries": [{"field": "r", "source": {"kind": "derive", "fn": "entity_refs",
                                                        "args": [{"$input": "kind"}, {"$input": "caller.roles"}]}}],
                "primitives": {"entity_refs": {"class": "pure"}}}
        with pytest.raises(DerivePlanError, match="literal Cedar entity type name"):
            validate_derive_plan(plan)
        plan["entries"][0]["source"]["args"] = ["IdpRole"]
        with pytest.raises(DerivePlanError, match=r"takes \(type, ids\)"):
            validate_derive_plan(plan)
        plan["entries"][0]["source"]["args"] = ["IdpRole", {"$input": "caller.roles"}]
        validate_derive_plan(plan)

    def test_the_hierarchy_plan_declares_exactly_what_it_derives(self):
        plan = json.loads((HIERARCHY / "fetchplan.json").read_text())
        assert set(plan["primitives"]) == {"entity_refs", "verify_eddsa"}
        validate_derive_plan(plan)

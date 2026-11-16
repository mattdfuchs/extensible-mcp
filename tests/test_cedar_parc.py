# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The PARC mapping (#13): principal is the caller, action is the tool,
resource is the server type, everything evidential is ``context``; and for a
bundle with no ``schema.json`` -- every bundle here -- ``in`` is refused at
load, since such a bundle declares no hierarchy and a rule that tests
membership against none is silently inert. A bundle that ships a schema may
test ``in``; ``test_cedar_store.py`` covers that side."""

from __future__ import annotations

from pathlib import Path

import pytest

from extensible_mcp.cedar_policy import (
    REQUEST_HEAD,
    CedarPolicy,
    CedarPolicyError,
    request_head,
)
from extensible_mcp.wasm_policy import PolicyEvaluationError

PROBE = "!(context has probe)"


def _engine(tmp_path: Path, policy: str, package: str = "t") -> CedarPolicy:
    (tmp_path / "policy.cedar").write_text(policy)
    return CedarPolicy(tmp_path / "policy.cedar", package=package)


def _permit(scope: str, when: str = "true") -> str:
    """One permit-decides tier, with the probe-pass forbid the shape needs."""
    return (
        f'@tier("solo")\npermit ({scope}) when {{ {PROBE} && ({when}) }};\n'
        '@id("solo.never")\nforbid (principal, action, resource) '
        "when { context has probe && false };\n"
    )


def _allows(engine: CedarPolicy, input_obj: dict) -> bool:
    allow, = (e for e in engine.entrypoints() if e.endswith("/allow"))
    return engine.query(input_obj, allow) == [{"result": True}]


# -- `in` is refused at load --------------------------------------------- #

class TestInIsRefused:
    def test_in_a_when_clause(self, tmp_path):
        policy = _permit("principal, action, resource", 'principal in Group::"kids"')
        with pytest.raises(CedarPolicyError, match=r"line 2: `in` is refused"):
            _engine(tmp_path, policy)

    def test_in_the_scope(self, tmp_path):
        policy = _permit('principal in Group::"kids", action, resource')
        with pytest.raises(CedarPolicyError, match="`in` is refused"):
            _engine(tmp_path, policy)

    def test_in_a_comment_a_string_or_an_identifier_is_not_the_token(self, tmp_path):
        policy = (
            "// membership in a group is not expressible here\n"
            + _permit(
                "principal, action, resource",
                'context has inner && context.inner.contains("in the string")',
            )
        )
        engine = _engine(tmp_path, policy)
        assert _allows(engine, {"inner": ["in the string"]})

    def test_the_hazard_it_closes(self, tmp_path):
        """What cedarpy alone does with the construct: the forbid is inert
        and nothing reports it. Pinned so the refusal has its reason."""
        import cedarpy

        policy = (
            "permit (principal, action, resource);\n"
            'forbid (principal in Group::"kids", action, resource) when { true };\n'
        )
        res = cedarpy.is_authorized({**REQUEST_HEAD, "context": {}}, policy, [])
        assert res.decision == cedarpy.Decision.Allow and not list(res.diagnostics.errors)


# -- the head ------------------------------------------------------------- #

class TestRequestHead:
    def test_defaults_when_the_input_says_nothing(self):
        head = request_head({}, "family_spend_prod")
        assert head == {
            "principal": 'Caller::"anonymous"',
            "action": 'Action::"call"',
            "resource": 'Server::"family_spend_prod"',
        }

    def test_the_caller_and_the_tool_fill_it(self):
        head = request_head({"caller": {"sub": "alice", "roles": ["parent"]}, "tool": "order_pizza"}, "t")
        assert head["principal"] == 'Caller::"alice"' and head["action"] == 'Action::"order_pizza"'

    def test_a_caller_without_a_sub_stays_anonymous(self):
        assert request_head({"caller": {"roles": ["parent"]}}, "t")["principal"] == 'Caller::"anonymous"'

    def test_ids_are_escaped_as_cedar_strings(self):
        head = request_head({"tool": 'or"der\\pizza'}, "t")
        assert head["action"] == 'Action::"or\\"der\\\\pizza"'

    def test_a_control_character_is_a_fault(self):
        with pytest.raises(PolicyEvaluationError, match="control character"):
            request_head({"tool": "order\npizza"}, "t")


class TestActionIsTheTool:
    def test_a_scope_on_the_action_decides_by_tool(self, tmp_path):
        engine = _engine(tmp_path, _permit('principal, action == Action::"order_pizza", resource'))
        assert _allows(engine, {"tool": "order_pizza"})
        assert not _allows(engine, {"tool": "send"})
        assert not _allows(engine, {})

    def test_an_escaped_tool_name_evaluates_without_a_diagnostic(self, tmp_path):
        engine = _engine(tmp_path, _permit('principal, action == Action::"order_pizza", resource'))
        assert not _allows(engine, {"tool": 'or"der\\pizza'})


class TestPrincipalIsTheCaller:
    def test_a_scope_on_the_principal_decides_by_sub(self, tmp_path):
        engine = _engine(tmp_path, _permit('principal == Caller::"alice", action, resource'))
        assert _allows(engine, {"caller": {"sub": "alice"}})
        assert not _allows(engine, {"caller": {"sub": "bob"}})
        assert not _allows(engine, {})

    def test_the_callers_roles_are_read_in_the_when_clause(self, tmp_path):
        engine = _engine(tmp_path, _permit(
            "principal, action, resource",
            'context has caller && context.caller.roles.contains("parent")',
        ))
        assert _allows(engine, {"caller": {"sub": "alice", "roles": ["parent"]}})
        assert not _allows(engine, {"caller": {"sub": "alice", "roles": ["child"]}})
        # No principal: the guard fails closed, and nothing is reported as a fault.
        assert not _allows(engine, {})

    def test_an_unguarded_read_of_the_caller_with_no_principal_is_a_fault(self, tmp_path):
        """The ``has`` guard is the author's; without it, an absent caller is
        an evaluation diagnostic, which the engine treats as a fault, never a
        quiet denial."""
        engine = _engine(tmp_path, _permit(
            "principal, action, resource", 'context.caller.roles.contains("parent")',
        ))
        with pytest.raises(PolicyEvaluationError, match="diagnostic"):
            engine.query({}, "t/allow")

    def test_anonymous_is_a_head_a_rule_may_name(self, tmp_path):
        engine = _engine(tmp_path, _permit('principal == Caller::"anonymous", action, resource'))
        assert _allows(engine, {})
        assert not _allows(engine, {"caller": {"sub": "alice"}})


class TestResourceIsTheServerType:
    def test_the_package_is_the_resource(self, tmp_path):
        policy = _permit('principal, action, resource == Server::"family_spend_prod"')
        assert _allows(_engine(tmp_path, policy, package="family_spend_prod"), {})
        (tmp_path / "other").mkdir()
        assert not _allows(_engine(tmp_path / "other", policy, package="family_spend_invoice"), {})

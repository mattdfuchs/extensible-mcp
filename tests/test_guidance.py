# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the "why it failed" renderer (guidance × failed-check ids).

Synthetic guidance only; the end-to-end path against the real
family_spend_prod bundle is covered in test_vc_policy.py."""

from __future__ import annotations

from extensible_mcp.guidance import render_denial


def _guidance(*, tier1_remedy: str = "re-promptable") -> dict:
    return {
        "tiers": [
            {
                "tier": 0,
                "checks": [
                    {
                        "id": "t0.c0",
                        "sentence": "the amount is over the self-approval limit",
                        "remedy_class": "re-promptable",
                        "condition": "amountCents <= 1000",
                    },
                    {
                        "id": "t0.c1",
                        "sentence": "outside local business hours",
                        "remedy_class": "terminal",
                        "condition": "business_hours(now)",
                    },
                ],
            },
            {
                "tier": 1,
                "checks": [
                    {
                        "id": "t1.c0",
                        "sentence": "the approver signature is missing or invalid",
                        "remedy_class": tier1_remedy,
                        "condition": "verify(authorizationVC)",
                    },
                ],
            },
        ],
        "call_guards": [
            {
                "field": "authorizationVC",
                "always": False,
                "required_in_tiers": [1],
                "deciding_checks": [],
            },
        ],
        "call_credentials": [
            {
                "field": "authorizationVC",
                "issuer_role": "parent",
                "role_checks": [],
                "depends_on": [],
            },
        ],
    }


def test_disjunctive_grouping_preserves_paths():
    msg = render_denial(_guidance(), {"t0.c0", "t1.c0"})
    assert "- Path 1: the amount is over the self-approval limit." in msg
    assert "- Path 2: the approver signature is missing or invalid." in msg
    assert "one of these paths" in msg
    assert "retry" in msg


def test_tier_without_failed_ids_gets_placeholder_not_silence():
    # The policy denied, so every tier failed — a tier contributing no ids
    # failed at unnamed checks and must not read as satisfied.
    msg = render_denial(_guidance(), {"t0.c0"})
    assert "- Path 2: other conditions on this path were not met." in msg


def test_unknown_id_renders_as_gap_never_a_lie():
    msg = render_denial(_guidance(), {"t0.c0", "t9.c9"})
    assert "Other unnamed conditions also failed." in msg
    assert "t9.c9" not in msg


def test_absent_credential_named_from_guards_with_role():
    msg = render_denial(_guidance(), {"t0.c0"}, absent_fields={"authorizationVC"})
    assert "provide `authorizationVC`, signed by the parent," in msg
    # named on the tier that requires it, not on the solo tier
    path2 = next(line for line in msg.splitlines() if line.startswith("- Path 2"))
    assert "authorizationVC" in path2


def test_remedy_aggregation_any_openable_path_means_retry():
    # Path 1 fails terminally, but path 2 is openable by re-prompting.
    msg = render_denial(_guidance(), {"t0.c1", "t1.c0"})
    assert "retry" in msg and "do not retry" not in msg


def test_remedy_aggregation_all_paths_terminal_means_do_not_retry():
    msg = render_denial(_guidance(tier1_remedy="terminal"), {"t0.c1", "t1.c0"})
    assert "do not retry" in msg


def test_missing_remedy_class_defaults_to_repromptable():
    guidance = _guidance()
    for tier in guidance["tiers"]:
        for check in tier["checks"]:
            del check["remedy_class"]
    msg = render_denial(guidance, {"t0.c1", "t1.c0"})
    assert "retry" in msg and "do not retry" not in msg


def test_returns_none_when_unrenderable():
    assert render_denial(None, {"t0.c0"}) is None
    assert render_denial({}, {"t0.c0"}) is None
    assert render_denial(_guidance(), set()) is None
    # ...but absent-credential information alone is renderable
    assert render_denial(_guidance(), set(), absent_fields={"authorizationVC"}) is not None

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests for the role -> wallet IssuerRegistry."""

from __future__ import annotations

from pathlib import Path

from extensible_mcp.bundle import PolicyBundle
from extensible_mcp.issuer import IssuerRegistry

PROD_DIR = Path(__file__).parent / "fixtures" / "family_spend_prod"


def test_url_for_role():
    reg = IssuerRegistry({"kid": "https://kid.wallet", "parent": "https://parent.wallet"})
    assert reg.url_for("parent") == "https://parent.wallet"
    assert reg.url_for("grandparent") is None
    assert "kid" in reg and "grandparent" not in reg
    assert set(reg.roles()) == {"kid", "parent"}


def test_from_positional_migration_shim():
    reg = IssuerRegistry.from_positional(
        originator_url="https://o", approver_url="https://a"
    )
    assert reg.url_for("kid") == "https://o"
    assert reg.url_for("parent") == "https://a"


def test_from_positional_custom_roles():
    reg = IssuerRegistry.from_positional(
        originator_url="https://o",
        approver_url="https://a",
        originator_role="employee",
        approver_role="manager",
    )
    assert set(reg.roles()) == {"employee", "manager"}


def test_missing_roles_admission_check_against_bundle():
    # The bundle derives its issuer roles from the enforced role tags; the
    # registry must cover them all before a deployment admits the bundle.
    bundle = PolicyBundle.load(PROD_DIR)
    assert bundle.issuer_roles() == {"child", "parent"}

    full = IssuerRegistry({"child": "https://k", "parent": "https://p"})
    assert full.missing_roles(bundle.issuer_roles()) == []

    partial = IssuerRegistry({"child": "https://k"})
    assert partial.missing_roles(bundle.issuer_roles()) == ["parent"]

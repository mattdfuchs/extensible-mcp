# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""First boot on the organization's identity provider binds each member's
account into the membership the admin signs; without a provider the
memberships are as they always were."""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

from extensible_mcp_vc.oauth import bound_accounts, realm_user_ids

_EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
sys.path.insert(0, str(_EXAMPLES))
import setup as setup_script  # noqa: E402

REALM = Path(__file__).resolve().parents[1] / "deploy" / "keycloak" / "household-realm.json"
ISSUER = "http://localhost:8080/realms/household"


def _payload(jwt: str) -> dict:
    seg = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def _run_setup(tmp_path, monkeypatch, *argv):
    ws = tmp_path / "ws"
    monkeypatch.setattr(sys, "argv", ["setup", "--workspace", str(ws), *argv])
    setup_script.main()
    return {
        "child": _payload((ws / "memberships" / "kid.jwt").read_text().strip()),
        "parent": _payload((ws / "memberships" / "parent.jwt").read_text().strip()),
    }


def test_bound_accounts_come_from_the_realms_pinned_ids():
    ids = realm_user_ids(REALM)
    assert bound_accounts(ISSUER + "/", REALM) == {
        "parent": [(ISSUER, ids["parent"])],
        "child": [(ISSUER, ids["child"])],
    }


def test_with_an_issuer_each_membership_names_the_members_account(tmp_path, monkeypatch):
    monkeypatch.delenv("APPROVAL_ISSUER", raising=False)
    ms = _run_setup(tmp_path, monkeypatch, "--issuer", ISSUER)
    ids = realm_user_ids(REALM)
    for role in ("child", "parent"):
        subject = ms[role]["vc"]["credentialSubject"]
        assert subject["role"] == role
        assert subject["accounts"] == [{"idp": ISSUER, "account": ids[role]}]


def test_the_environment_configures_the_issuer_the_same_way(tmp_path, monkeypatch):
    monkeypatch.setenv("APPROVAL_ISSUER", ISSUER)
    ms = _run_setup(tmp_path, monkeypatch)
    assert ms["child"]["vc"]["credentialSubject"]["accounts"][0]["account"] == realm_user_ids(REALM)["child"]


def test_without_an_issuer_the_memberships_are_unbound(tmp_path, monkeypatch):
    monkeypatch.delenv("APPROVAL_ISSUER", raising=False)
    ms = _run_setup(tmp_path, monkeypatch)
    for role in ("child", "parent"):
        assert "accounts" not in ms[role]["vc"]["credentialSubject"]

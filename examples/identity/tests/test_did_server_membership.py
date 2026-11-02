# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests for FamilyMembership VC construction and signing."""

from __future__ import annotations

from household_identity.common import jws, keys
from household_identity.did_server.membership import make_membership_vc


class TestMakeMembershipVC:
    def test_payload_shape(self):
        payload = make_membership_vc(
            admin_did="did:web:family.example.com",
            member_did="did:key:z6Mkabc",
            role="child",
        )
        assert payload["iss"] == "did:web:family.example.com"
        assert payload["sub"] == "did:key:z6Mkabc"
        assert payload["nbf"] < payload["exp"]
        assert payload["jti"].startswith("urn:uuid:")
        cs = payload["vc"]["credentialSubject"]
        assert cs == {
            "id": "did:key:z6Mkabc",
            "role": "child",
            "family": "did:web:family.example.com",
        }
        assert "FamilyMembership" in payload["vc"]["type"]

    def test_default_ttl_is_one_year(self):
        payload = make_membership_vc(
            admin_did="did:web:f", member_did="did:key:z", role="parent"
        )
        assert payload["exp"] - payload["nbf"] == 365 * 24 * 3600

    def test_custom_ttl(self):
        payload = make_membership_vc(
            admin_did="did:web:f",
            member_did="did:key:z",
            role="parent",
            ttl_seconds=60,
        )
        assert payload["exp"] - payload["nbf"] == 60

    def test_sign_verify_roundtrip(self):
        admin_key = keys.generate_keypair()
        payload = make_membership_vc(
            admin_did="did:web:family.example.com",
            member_did="did:key:z6Mkabc",
            role="parent",
        )
        token = jws.sign_jwt(payload, key=admin_key, kid="did:web:family.example.com")
        claims = jws.verify_jwt(token, key=admin_key.public_key())
        assert claims["sub"] == "did:key:z6Mkabc"
        assert claims["vc"]["credentialSubject"]["role"] == "parent"


class TestAccounts:
    def test_accounts_bind_identity_provider_subjects_to_the_member(self):
        payload = make_membership_vc(
            admin_did="did:web:family.example.com",
            member_did="did:key:z6Mkabc",
            role="child",
            accounts=[("https://idp.example/realms/household", "a3f1"), ("https://other.example", "u-9")],
        )
        assert payload["vc"]["credentialSubject"]["accounts"] == [
            {"idp": "https://idp.example/realms/household", "account": "a3f1"},
            {"idp": "https://other.example", "account": "u-9"},
        ]
        # The role binding is untouched by the second binding.
        assert payload["vc"]["credentialSubject"]["role"] == "child"

    def test_no_accounts_means_no_field_so_older_credentials_are_unchanged(self):
        for accounts in (None, []):
            payload = make_membership_vc(
                admin_did="did:web:f", member_did="did:key:z", role="parent", accounts=accounts
            )
            assert "accounts" not in payload["vc"]["credentialSubject"]

    def test_a_malformed_account_is_refused(self):
        import pytest

        with pytest.raises(ValueError, match="non-empty strings"):
            make_membership_vc(
                admin_did="did:web:f", member_did="did:key:z", role="parent", accounts=[("", "x")]
            )

    def test_the_cli_binds_accounts_and_splits_on_the_last_equals(self, tmp_path, capsys):
        from household_identity.did_server.cli import main

        assert main(["init", "--did", "did:web:f", "--keys-dir", str(tmp_path / "k"),
                     "--public-dir", str(tmp_path / "p")]) == 0
        capsys.readouterr()
        assert main([
            "issue-membership", "--did", "did:web:f", "--keys-dir", str(tmp_path / "k"),
            "--member", "did:key:z6Mkabc", "--role", "child",
            "--account", "https://idp.example/realms/a=b?x=1=acct-1",
        ]) == 0
        token = capsys.readouterr().out.strip()
        admin_key = keys.load_private_jwk(tmp_path / "k" / "admin.jwk")
        claims = jws.verify_jwt(token, key=admin_key.public_key())
        assert claims["vc"]["credentialSubject"]["accounts"] == [
            {"idp": "https://idp.example/realms/a=b?x=1", "account": "acct-1"}
        ]
        assert main([
            "issue-membership", "--did", "did:web:f", "--keys-dir", str(tmp_path / "k"),
            "--member", "did:key:z6Mkabc", "--role", "child", "--account", "nonsense",
        ]) == 1

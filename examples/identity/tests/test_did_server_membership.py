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

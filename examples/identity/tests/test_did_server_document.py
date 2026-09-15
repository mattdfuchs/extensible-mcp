# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests for the DID document builder."""

from __future__ import annotations

from household_identity.common import keys
from household_identity.did_server.document import make_did_document


class TestMakeDidDocument:
    def test_top_level_shape(self):
        key = keys.generate_keypair()
        doc = make_did_document(did="did:web:family.example.com", key=key)
        assert doc["@context"] == ["https://www.w3.org/ns/did/v1"]
        assert doc["id"] == "did:web:family.example.com"

    def test_verification_method_embeds_public_jwk(self):
        key = keys.generate_keypair()
        doc = make_did_document(did="did:web:family.example.com", key=key)
        vm = doc["verificationMethod"][0]
        assert vm["id"] == "did:web:family.example.com#key-1"
        assert vm["type"] == "JsonWebKey2020"
        assert vm["controller"] == "did:web:family.example.com"
        assert vm["publicKeyJwk"] == keys.public_jwk(key)
        # public JWK never carries the private 'd' component
        assert "d" not in vm["publicKeyJwk"]

    def test_assertion_and_authentication_reference_vm(self):
        key = keys.generate_keypair()
        doc = make_did_document(did="did:web:family.example.com", key=key)
        assert doc["assertionMethod"] == ["did:web:family.example.com#key-1"]
        assert doc["authentication"] == ["did:web:family.example.com#key-1"]

    def test_custom_key_id_suffix(self):
        key = keys.generate_keypair()
        doc = make_did_document(
            did="did:web:family.example.com", key=key, key_id_suffix="admin"
        )
        assert doc["verificationMethod"][0]["id"] == "did:web:family.example.com#admin"
        assert doc["assertionMethod"] == ["did:web:family.example.com#admin"]

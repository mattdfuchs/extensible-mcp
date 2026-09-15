# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests for the did:web resolver and URL mapping."""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from household_identity.common import keys
from household_identity.did_server.document import make_did_document

from extensible_mcp_vc.did_resolver import (
    DidResolutionError,
    DidWebResolver,
    did_web_url,
)


class TestDidWebUrl:
    def test_bare_host_maps_to_well_known(self):
        assert (
            did_web_url("did:web:family.example.com")
            == "https://family.example.com/.well-known/did.json"
        )

    def test_subpath_maps_to_segmented_path(self):
        assert (
            did_web_url("did:web:example.com:user:alice")
            == "https://example.com/user/alice/did.json"
        )

    def test_url_encoded_port_decodes(self):
        assert (
            did_web_url("did:web:example.com%3A3000")
            == "https://example.com:3000/.well-known/did.json"
        )

    def test_rejects_non_did_web(self):
        with pytest.raises(DidResolutionError):
            did_web_url("did:key:z6Mkabc")


class TestDidWebResolver:
    async def test_preload_serves_without_fetching(self):
        calls: list[str] = []

        async def boom_fetcher(did: str) -> dict[str, Any]:
            calls.append(did)
            raise AssertionError("fetcher should not be called")

        resolver = DidWebResolver(fetcher=boom_fetcher)
        resolver.preload("did:web:x", {"id": "did:web:x"})
        doc = await resolver.resolve("did:web:x")
        assert doc == {"id": "did:web:x"}
        assert calls == []

    async def test_preloaded_entries_never_expire(self):
        """Static trust-anchor configuration must outlive the normal TTL."""
        calls: list[str] = []

        async def boom_fetcher(did: str) -> dict[str, Any]:
            calls.append(did)
            raise AssertionError("fetcher must not run for preloaded DIDs")

        clock = {"t": 0.0}
        resolver = DidWebResolver(
            cache_ttl_seconds=10,
            fetcher=boom_fetcher,
            clock=lambda: clock["t"],
        )
        resolver.preload("did:web:trust-anchor", {"id": "did:web:trust-anchor"})
        # Jump well past the TTL — a fetched entry would expire here.
        clock["t"] = 999_999.0
        doc = await resolver.resolve("did:web:trust-anchor")
        assert doc == {"id": "did:web:trust-anchor"}
        assert calls == []

    async def test_fetch_then_cache(self):
        clock = {"t": 0.0}
        fetches: list[str] = []

        async def fetcher(did: str) -> dict[str, Any]:
            fetches.append(did)
            return {"id": did}

        resolver = DidWebResolver(
            cache_ttl_seconds=10, fetcher=fetcher, clock=lambda: clock["t"]
        )
        await resolver.resolve("did:web:x")
        clock["t"] = 5.0
        await resolver.resolve("did:web:x")  # within TTL
        assert fetches == ["did:web:x"]
        clock["t"] = 11.0
        await resolver.resolve("did:web:x")  # past TTL
        assert fetches == ["did:web:x", "did:web:x"]

    async def test_public_key_returns_ed25519(self):
        admin_key = keys.generate_keypair()
        doc = make_did_document(did="did:web:family.example.com", key=admin_key)
        resolver = DidWebResolver()
        resolver.preload("did:web:family.example.com", doc)
        pub = await resolver.public_key("did:web:family.example.com")
        assert isinstance(pub, Ed25519PublicKey)
        # Same raw bytes as the admin's public key
        assert pub.public_bytes_raw() == admin_key.public_key().public_bytes_raw()

    async def test_kid_filter_matches_verification_method_id(self):
        admin_key = keys.generate_keypair()
        doc = make_did_document(
            did="did:web:f.example.com", key=admin_key, key_id_suffix="admin"
        )
        resolver = DidWebResolver()
        resolver.preload("did:web:f.example.com", doc)
        pub = await resolver.public_key(
            "did:web:f.example.com", kid="did:web:f.example.com#admin"
        )
        assert isinstance(pub, Ed25519PublicKey)
        with pytest.raises(DidResolutionError):
            await resolver.public_key(
                "did:web:f.example.com", kid="did:web:f.example.com#nope"
            )

    async def test_missing_verification_method_raises(self):
        resolver = DidWebResolver()
        resolver.preload("did:web:empty", {"id": "did:web:empty"})
        with pytest.raises(DidResolutionError):
            await resolver.public_key("did:web:empty")

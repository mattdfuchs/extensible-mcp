# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests for the did:web resolver + per-membership admin-key attachment."""

from __future__ import annotations

import pytest

from extensible_mcp.didweb import (
    DidResolutionError,
    DidWebResolver,
    did_web_to_url,
)
from tests import vc_helpers as vc

ADMIN_DID = "did:web:admin.example"
UNTRUSTED_DID = "did:web:evil.example"


@pytest.fixture(scope="module")
def admin_key():
    return vc.new_key()


def _did_doc(key) -> dict:
    return {
        "id": ADMIN_DID,
        "verificationMethod": [
            {
                "id": f"{ADMIN_DID}#key-1",
                "type": "JsonWebKey2020",
                "controller": ADMIN_DID,
                "publicKeyJwk": key.as_dict(private=False),
            }
        ],
        "assertionMethod": [f"{ADMIN_DID}#key-1"],
    }


def _resolver(admin_key, **kw):
    calls = []

    async def fetcher(url):
        calls.append(url)
        return _did_doc(admin_key)

    r = DidWebResolver([ADMIN_DID], fetcher=fetcher, **kw)
    return r, calls


def test_did_web_to_url_plain():
    assert did_web_to_url("did:web:example.com") == "https://example.com/.well-known/did.json"


def test_did_web_to_url_path_and_port():
    assert did_web_to_url("did:web:example.com:a:b") == "https://example.com/a/b/did.json"
    assert did_web_to_url("did:web:example.com%3A3000") == "https://example.com:3000/.well-known/did.json"


async def test_resolves_trusted_admin_to_jwk(admin_key):
    r, calls = _resolver(admin_key)
    jwk = await r.public_jwk(ADMIN_DID)
    assert jwk == admin_key.as_dict(private=False)
    assert calls == ["https://admin.example/.well-known/did.json"]


async def test_untrusted_did_returns_none_without_fetch(admin_key):
    r, calls = _resolver(admin_key)
    assert await r.public_jwk(UNTRUSTED_DID) is None
    assert calls == []  # SSRF guard: never fetched


async def test_trusted_but_unresolvable_fails_closed(admin_key):
    async def boom(url):
        raise OSError("connection refused")

    r = DidWebResolver([ADMIN_DID], fetcher=boom)
    with pytest.raises(DidResolutionError):
        await r.public_jwk(ADMIN_DID)


async def test_document_without_ed25519_key_fails_closed():
    async def fetcher(url):
        return {"id": ADMIN_DID, "verificationMethod": []}

    r = DidWebResolver([ADMIN_DID], fetcher=fetcher)
    with pytest.raises(DidResolutionError):
        await r.public_jwk(ADMIN_DID)


async def test_caches_within_ttl(admin_key):
    r, calls = _resolver(admin_key, cache_ttl_seconds=1000, clock=lambda: 0.0)
    await r.public_jwk(ADMIN_DID)
    await r.public_jwk(ADMIN_DID)
    assert len(calls) == 1  # fetched once, served from cache


async def test_preresolved_skips_fetch(admin_key):
    jwk = admin_key.as_dict(private=False)
    r = DidWebResolver([ADMIN_DID], fetcher=None, preresolved={ADMIN_DID: jwk})
    assert await r.public_jwk(ADMIN_DID) == jwk  # no fetcher needed


async def test_attach_admin_key_trusted(admin_key):
    r, _ = _resolver(admin_key)
    membership = {"jws": "x.y.z", "claims": {"iss": ADMIN_DID, "sub": "did:key:kid", "role": "kid"}}
    enriched = await r.attach_admin_key(membership)
    import json
    # adminKey is a serialized JWK string
    assert json.loads(enriched["adminKey"]) == admin_key.as_dict(private=False)
    assert enriched["claims"] == membership["claims"]  # original preserved


async def test_attach_admin_key_untrusted_is_none(admin_key):
    r, _ = _resolver(admin_key)
    membership = {"jws": "x.y.z", "claims": {"iss": UNTRUSTED_DID, "sub": "did:key:kid"}}
    enriched = await r.attach_admin_key(membership)
    assert enriched["adminKey"] is None  # policy will deny on the missing key

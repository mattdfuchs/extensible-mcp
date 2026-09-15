# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the DID server FastAPI app."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from household_identity.common import keys
from household_identity.did_server.document import make_did_document
from household_identity.did_server.server import (
    DID_DOCUMENT_MEDIA_TYPE,
    create_app,
)


@pytest.fixture
def did():
    return "did:web:family.example.com"


@pytest.fixture
def admin_key():
    return keys.generate_keypair()


@pytest.fixture
def doc_path(tmp_path: Path, did: str, admin_key) -> Path:
    path = tmp_path / "public" / ".well-known" / "did.json"
    path.parent.mkdir(parents=True)
    doc = make_did_document(did=did, key=admin_key)
    path.write_text(json.dumps(doc, indent=2))
    return path


class TestInfoEndpoint:
    def test_returns_did_and_document_path(self, doc_path: Path, did: str):
        client = TestClient(create_app(did_document_path=doc_path, did=did))
        r = client.get("/")
        assert r.status_code == 200
        assert r.json() == {"did": did, "document": "/.well-known/did.json"}


class TestDidDocumentEndpoint:
    def test_serves_did_document(self, doc_path: Path, did: str, admin_key):
        client = TestClient(create_app(did_document_path=doc_path, did=did))
        r = client.get("/.well-known/did.json")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith(DID_DOCUMENT_MEDIA_TYPE)
        body = r.json()
        assert body["id"] == did
        assert body["verificationMethod"][0]["publicKeyJwk"] == keys.public_jwk(
            admin_key
        )

    def test_missing_document_returns_500(self, tmp_path: Path, did: str):
        missing = tmp_path / "nope" / "did.json"
        client = TestClient(create_app(did_document_path=missing, did=did))
        r = client.get("/.well-known/did.json")
        assert r.status_code == 500

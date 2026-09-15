# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""FastAPI app that serves a did:web admin's DID document.

For ``did:web:family.example.com`` the resolver fetches
``https://family.example.com/.well-known/did.json``; this app is what answers
that fetch in development. In production the document is typically served by
any static host.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

DID_DOCUMENT_MEDIA_TYPE = "application/did+json"


def create_app(*, did_document_path: Path, did: str) -> FastAPI:
    app = FastAPI(title=f"household-identity DID server ({did})")

    @app.get("/")
    async def info() -> dict[str, str]:
        return {"did": did, "document": "/.well-known/did.json"}

    @app.get("/.well-known/did.json")
    async def did_document() -> FileResponse:
        if not did_document_path.exists():
            raise HTTPException(
                status_code=500, detail=f"did document missing at {did_document_path}"
            )
        return FileResponse(did_document_path, media_type=DID_DOCUMENT_MEDIA_TYPE)

    return app

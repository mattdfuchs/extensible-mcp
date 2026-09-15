# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""did:web resolver with an in-memory TTL cache.

did:web maps a DID to an HTTPS URL holding a DID document; the resolver
fetches the document once per cache window. For Ed25519 verification methods
the document's ``publicKeyJwk`` is enough to reconstruct an Ed25519PublicKey
without any extra crypto machinery.
"""

from __future__ import annotations

import time
import urllib.parse
from typing import Any, Awaitable, Callable

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from household_identity.common.keys import from_jwk


class DidResolutionError(Exception):
    pass


Fetcher = Callable[[str], Awaitable[dict[str, Any]]]


def did_web_url(did: str) -> str:
    """Translate a did:web DID into the HTTPS URL of its document."""
    if not did.startswith("did:web:"):
        raise DidResolutionError(f"not a did:web: {did!r}")
    parts = did.removeprefix("did:web:").split(":")
    host = urllib.parse.unquote(parts[0])
    if len(parts) == 1:
        return f"https://{host}/.well-known/did.json"
    path = "/".join(urllib.parse.unquote(p) for p in parts[1:])
    return f"https://{host}/{path}/did.json"


async def _default_fetcher(did: str) -> dict[str, Any]:
    url = did_web_url(did)
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(url)
    if r.status_code != 200:
        raise DidResolutionError(f"{did} returned HTTP {r.status_code} from {url}")
    return r.json()


class DidWebResolver:
    def __init__(
        self,
        *,
        cache_ttl_seconds: int = 3600,
        fetcher: Fetcher | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._cache_ttl = cache_ttl_seconds
        self._fetcher = fetcher or _default_fetcher
        self._clock = clock

    def preload(self, did: str, document: dict[str, Any]) -> None:
        """Cache a DID document permanently.

        Preloaded entries represent static configuration (e.g. an admin's
        ``did:web`` document baked into the proxy at startup) and must never
        expire — otherwise after ``cache_ttl_seconds`` the next verification
        would trigger an HTTPS fetch that for a private trust anchor like
        ``did:web:family.example.com`` simply doesn't exist on the public
        internet. Storing the timestamp as ``+inf`` makes the TTL check in
        :meth:`resolve` permanently satisfied for this entry.
        """
        self._cache[did] = (float("inf"), document)

    async def resolve(self, did: str) -> dict[str, Any]:
        now = self._clock()
        cached = self._cache.get(did)
        if cached and now - cached[0] < self._cache_ttl:
            return cached[1]
        doc = await self._fetcher(did)
        self._cache[did] = (now, doc)
        return doc

    async def public_key(
        self, did: str, *, kid: str | None = None
    ) -> Ed25519PublicKey:
        doc = await self.resolve(did)
        for vm in doc.get("verificationMethod", []):
            if kid is not None and vm.get("id") != kid:
                continue
            jwk = vm.get("publicKeyJwk")
            if jwk is None:
                continue
            key = from_jwk(jwk)
            if isinstance(key, Ed25519PublicKey):
                return key
            raise DidResolutionError(
                f"verification method in {did} is not Ed25519 (got {type(key).__name__})"
            )
        raise DidResolutionError(
            f"no Ed25519 verification method in {did} document"
            + (f" with kid={kid}" if kid else "")
        )

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Resolve ``did:web`` admin DIDs to their Ed25519 JWK, for membership chaining.

The production VC policy verifies each signer's membership against the key of
the ``did:web`` admin that issued it (seam 2).
That resolution is HTTPS I/O, so it cannot live inside the wasm policy — the
proxy does it here and attaches the resolved key onto each membership
(`membership.adminKey`), giving the policy a *static* path to read.

Two safety properties:

- **SSRF guard.** Only DIDs in the configured trusted-admin set are resolved;
  an untrusted DID returns ``None`` without any network call, so the proxy
  never fetches an attacker-named domain. This is defense-in-depth, *not* a
  replacement for the policy's own ``iss ∈ trustedAdminDids`` check — a
  membership whose issuer is untrusted simply gets no ``adminKey`` and the
  policy denies it.
- **Fail-closed.** A trusted DID that cannot be resolved (network/parse
  failure, no Ed25519 key) raises ``DidResolutionError``; the caller treats an
  un-assembled input as a denial.

The HTTP fetch is injected (``fetcher``) so core takes no hard HTTP dependency
and tests run without network; a deployment supplies an httpx-backed fetcher.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from .wasm_policy import _key_from_did_key

logger = logging.getLogger("extensible_mcp.didweb")

# An async fetch of a did.json document by URL.
DidWebFetcher = Callable[[str], Awaitable[dict[str, Any]]]


class DidResolutionError(Exception):
    """A trusted did:web could not be resolved to a usable key (fail closed)."""


def did_web_to_url(did: str) -> str:
    """Map a ``did:web`` to its document URL (W3C did:web method).

    ``did:web:example.com`` → ``https://example.com/.well-known/did.json``;
    ``did:web:example.com:a:b`` → ``https://example.com/a/b/did.json``; a
    percent-encoded ``%3A`` in the host segment becomes a port colon.
    """
    if not did.startswith("did:web:"):
        raise DidResolutionError(f"not a did:web: {did!r}")
    segments = did[len("did:web:"):].split(":")
    host = segments[0].replace("%3A", ":").replace("%3a", ":")
    if not host:
        raise DidResolutionError(f"did:web has no host: {did!r}")
    if len(segments) == 1:
        return f"https://{host}/.well-known/did.json"
    return f"https://{host}/{'/'.join(segments[1:])}/did.json"


def ed25519_jwk_from_document(doc: dict[str, Any]) -> dict[str, Any] | None:
    """The first Ed25519 public JWK in a DID document, or ``None``.

    Public helper for deployments that hold pre-resolved DID *documents*
    (e.g. static config) and need to seed a resolver's ``preresolved``
    key map from them."""
    return _extract_ed25519_jwk(doc)


def _extract_ed25519_jwk(doc: dict[str, Any]) -> dict[str, Any] | None:
    """Pull the first Ed25519 public key from a DID document."""
    for vm in doc.get("verificationMethod", []):
        if not isinstance(vm, dict):
            continue
        jwk = vm.get("publicKeyJwk")
        if (
            isinstance(jwk, dict)
            and jwk.get("kty") == "OKP"
            and jwk.get("crv") == "Ed25519"
        ):
            return jwk
        mb = vm.get("publicKeyMultibase")
        if isinstance(mb, str) and mb.startswith("z"):
            derived = _key_from_did_key("did:key:" + mb)
            if derived is not None:
                return derived
    return None


class DidWebResolver:
    """Resolve trusted ``did:web`` admins to their Ed25519 JWK, cached."""

    def __init__(
        self,
        trusted_dids: list[str],
        *,
        fetcher: DidWebFetcher | None = None,
        cache_ttl_seconds: int = 3600,
        preresolved: dict[str, dict[str, Any]] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._trusted = set(trusted_dids)
        self._fetcher = fetcher
        self._ttl = cache_ttl_seconds
        self._clock = clock
        # did -> (jwk, expires_at). Preresolved entries never expire.
        self._cache: dict[str, tuple[dict[str, Any], float]] = {}
        for did, jwk in (preresolved or {}).items():
            self._cache[did] = (jwk, float("inf"))

    async def public_jwk(self, did: str) -> dict[str, Any] | None:
        """The admin's Ed25519 JWK, or ``None`` if the DID is not trusted.

        Raises ``DidResolutionError`` for a *trusted* DID that cannot be
        resolved (fail closed).
        """
        if did not in self._trusted:
            logger.warning("did:web %r is not in the trusted admin set; not resolving", did)
            return None

        cached = self._cache.get(did)
        if cached is not None and cached[1] > self._clock():
            return cached[0]

        if self._fetcher is None:
            raise DidResolutionError(
                f"no fetcher configured to resolve trusted admin {did!r}"
            )
        url = did_web_to_url(did)
        try:
            doc = await self._fetcher(url)
        except Exception as e:  # noqa: BLE001 - any fetch failure is fail-closed
            raise DidResolutionError(f"could not fetch {did} ({url}): {e}") from e
        jwk = _extract_ed25519_jwk(doc)
        if jwk is None:
            raise DidResolutionError(f"{did} document has no Ed25519 key")
        self._cache[did] = (jwk, self._clock() + self._ttl)
        return jwk

    async def attach_admin_key(self, membership: dict[str, Any]) -> dict[str, Any]:
        """Return ``membership`` with its issuer's resolved key as ``adminKey``.

        For the policy's static-path read (seam 2). ``adminKey`` is the
        **serialized JWK string** — the convention a policy's verify atom
        expects, an opaque string passed straight through rather than parsed
        proxy-side. An untrusted or issuer-less
        membership gets ``adminKey = None`` (the policy then denies); a
        trusted-but-unresolvable issuer propagates ``DidResolutionError``.
        """
        iss = membership.get("claims", {}).get("iss") if isinstance(membership, dict) else None
        jwk = await self.public_jwk(iss) if isinstance(iss, str) else None
        admin_key = json.dumps(jwk) if jwk is not None else None
        return {**membership, "adminKey": admin_key}

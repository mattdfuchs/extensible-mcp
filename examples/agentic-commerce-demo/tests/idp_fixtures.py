# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""A fake identity provider for the demo's tests: discovery, a JWKS and a
token endpoint behind an ``httpx2`` mock transport, served at an *internal*
base distinct from the issuer it names, and tokens minted with a local RSA
keypair shaped exactly as the committed realm's mappers emit them.

Not a test module (no ``test_`` prefix), so pytest imports but does not
collect it."""

from __future__ import annotations

from urllib.parse import parse_qs

import httpx2
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from joserfc.jwk import RSAKey

from extensible_mcp_vc.oauth import AUDIENCE, ROLES_CLAIM

ISSUER = "http://idp.test/realms/household"
INTERNAL = "http://idp.internal/realms/household"
KID = "realm-key-1"


class FakeProvider:
    """Discovery, JWKS and a token endpoint, as the realm publishes them, at
    the *internal* base only: a request to the public issuer from the service
    is the container mistake the rewrite exists to prevent."""

    def __init__(self, keypair: RSAKeyPair, *, issuer: str = ISSUER, internal: str = INTERNAL):
        jwk = RSAKey.import_key(keypair.public_key).as_dict()
        jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
        self.jwks = {"keys": [jwk]}
        self.issuer = issuer
        self.internal = internal
        self.requests: list[str] = []
        self.token_requests: list[dict[str, str]] = []
        self.token_response: tuple[int, dict] = (
            200, {"access_token": "provider-token", "token_type": "Bearer", "expires_in": 300}
        )
        self.discovery_issuer = issuer

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        url = str(request.url)
        self.requests.append(url)
        if url == f"{self.internal}/.well-known/openid-configuration":
            return httpx2.Response(200, json={
                "issuer": self.discovery_issuer,
                "authorization_endpoint": f"{self.issuer}/protocol/openid-connect/auth",
                "token_endpoint": f"{self.issuer}/protocol/openid-connect/token",
                "jwks_uri": f"{self.issuer}/protocol/openid-connect/certs",
            })
        if url == f"{self.internal}/protocol/openid-connect/certs":
            return httpx2.Response(200, json=self.jwks)
        if url == f"{self.internal}/protocol/openid-connect/token":
            form = {k: v for k, v in parse_qs(request.content.decode()).items()}
            self.token_requests.append({k: v[0] for k, v in form.items()})
            status, body = self.token_response
            return httpx2.Response(status, json=body)
        return httpx2.Response(404, json={"error": "not found", "url": url})




def mint(keypair, roles, *, amr=("hwk",), issuer=ISSUER, audience=AUDIENCE, sub="parent-uuid"):
    """A token shaped as the realm's mappers emit one."""
    claims = {ROLES_CLAIM: list(roles)}
    if amr is not None:
        claims["amr"] = list(amr)
    return keypair.create_token(
        subject=sub, issuer=issuer, audience=audience, additional_claims=claims, kid=KID
    )


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def mock_client(provider: FakeProvider) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(transport=httpx2.MockTransport(provider.handler))

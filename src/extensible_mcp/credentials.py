# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Downstream credentials acquired by an OAuth grant rather than read off disk.

A token in ``tokens_file`` is a long-lived bearer at rest: whoever reads the
file holds the credential until someone notices. This module replaces it with
an acquisition: the proxy authenticates itself to an authorization server and
is handed a short-lived access token, which lives only in memory.

Two grants ship, both of them RFC 6749 ``client_credentials`` at the token
endpoint, differing in how the proxy authenticates *as a client*:

- ``private_key_jwt`` (RFC 7523 §2.2) — the proxy signs a short-lived
  assertion with a private key the authorization server never sees. Nothing
  replayable is transmitted, so the credential cannot be harvested from
  traffic or logs.
- ``client_credentials`` — a client secret read from the environment. It
  relocates the liability rather than retiring it (a long-lived secret is
  still a secret), and ships because it is what most authorization servers
  are actually configured for.

What this earns is **no replayable secret at rest**, not *no secret at rest*:
``private_key_jwt`` still keeps a private key on disk. Only a workload
identity (a platform-attested, short-lived token) reaches the latter, and
that is deliberately not implemented here — every form of it is
deployment-specific. The seam is what makes it available later: a provider is
an object that returns a token, so "read the projected service-account token
and exchange it" is another provider, written without touching the proxy.

Acquisition and refresh live in the transport, as an ``httpx.Auth``
(:class:`OAuthGrantAuth`), not in proxy logic: the token is attached
per request and a 401 refreshes it in place.

The principal parameter
-----------------------

:meth:`CredentialProvider.token` takes a principal. There is exactly one
possible argument today — :data:`PROXY_ITSELF` — because the downstream
credential is a property of the proxy process: every caller shares one
downstream identity, and per-caller authorization is enforced in the proxy's
filters. A per-principal credential (RFC 8693 token exchange, where the
caller is ``sub`` and the proxy is ``act``) needs a principal to key on, and
the proxy has none yet. Taking the parameter now means that work *extends*
this seam instead of replacing it; providers reject any other value rather
than quietly treating it as the proxy.
"""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any, Final, Protocol, runtime_checkable

import httpx

from .types import CredentialConfig

logger = logging.getLogger(__name__)

GRANT_PRIVATE_KEY_JWT: Final = "private_key_jwt"
GRANT_CLIENT_CREDENTIALS: Final = "client_credentials"
#: The grants with working implementations. A grant outside this set is
#: refused at config load rather than ignored.
SUPPORTED_GRANTS: Final = (GRANT_PRIVATE_KEY_JWT, GRANT_CLIENT_CREDENTIALS)

CLIENT_ASSERTION_TYPE: Final = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

# A cached token stops being served this many seconds before its stated
# expiry, so a token that would expire in flight is re-acquired instead.
EXPIRY_SKEW_SECONDS: Final = 30.0
# How long a signed client assertion is valid. Short: it is used once,
# immediately, against one token endpoint.
ASSERTION_LIFETIME_SECONDS: Final = 60
# Timeout for the token request itself. An authorization server that does not
# answer promptly is a deployment fault, and failing is the fail-closed
# outcome: no token, no call.
TOKEN_REQUEST_TIMEOUT_SECONDS: Final = 10.0

# Curve -> JOSE algorithm for an EC client assertion.
_EC_ALGORITHMS: Final = {
    "secp256r1": "ES256",
    "secp384r1": "ES384",
    "secp521r1": "ES512",
}


class ProxyItself:
    """The type of the one principal a credential can be acquired for.

    Deliberately not a general ``Principal``: the proxy has no notion of a
    caller identity yet, and inventing one here would be a guess at the shape
    of work that has not been done. This is a sentinel type with a single
    instance, :data:`PROXY_ITSELF`.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "PROXY_ITSELF"


#: The proxy's own service identity: the only principal a provider accepts.
PROXY_ITSELF: Final = ProxyItself()


class CredentialError(Exception):
    """A credential could not be acquired.

    An engine fault, never a policy decision: it means the proxy cannot
    authenticate downstream, so the call does not happen.
    """


@runtime_checkable
class CredentialProvider(Protocol):
    """Resolves the downstream credential for one server, per call.

    ``force_refresh`` is how the transport says "the token I was given was
    refused" — the provider discards what it cached and acquires again.
    """

    async def token(self, principal: ProxyItself, *, force_refresh: bool = False) -> str:
        ...


def _require_proxy_principal(principal: object) -> None:
    if principal is not PROXY_ITSELF:
        raise CredentialError(
            f"Unsupported principal {principal!r}: the proxy can only acquire a "
            "credential for itself (extensible_mcp.credentials.PROXY_ITSELF). "
            "Per-principal credentials need a principal the proxy does not have yet."
        )


class _TokenEndpointProvider:
    """Shared machinery for the two shipping grants.

    Caches the acquired token until shortly before its stated expiry, and
    serializes acquisition so a burst of concurrent calls makes one token
    request rather than one each. Subclasses supply the client
    authentication half of the form body.
    """

    def __init__(
        self,
        *,
        name: str,
        token_endpoint: str,
        client_id: str,
        scope: str | None = None,
        audience: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = TOKEN_REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self.name = name
        self.token_endpoint = token_endpoint
        self.client_id = client_id
        self.scope = scope
        self.audience = audience
        self._transport = transport
        self._timeout = timeout
        self._lock = asyncio.Lock()
        self._token: str | None = None
        self._expires_at: float | None = None
        self._acquired_at: float | None = None

    @property
    def token_age_minutes(self) -> int:
        """How long the cached token has been held, for error reporting."""
        if self._acquired_at is None:
            return 0
        return int((time.monotonic() - self._acquired_at) / 60)

    def _usable(self) -> bool:
        if self._token is None:
            return False
        if self._expires_at is None:
            return True
        return time.monotonic() < self._expires_at - EXPIRY_SKEW_SECONDS

    def invalidate(self) -> None:
        self._token = None
        self._expires_at = None
        self._acquired_at = None

    async def token(self, principal: ProxyItself, *, force_refresh: bool = False) -> str:
        _require_proxy_principal(principal)
        async with self._lock:
            if force_refresh:
                self.invalidate()
            if self._usable():
                assert self._token is not None
                return self._token
            self.invalidate()
            form = dict(self._base_form())
            form.update(self._client_authentication())
            token, expires_in = await self._request_token(form)
            self._token = token
            self._acquired_at = time.monotonic()
            self._expires_at = (
                self._acquired_at + expires_in if expires_in is not None else None
            )
            logger.info(
                "Acquired a downstream token for credential %r via %s (expires_in=%s)",
                self.name,
                self.grant_description,
                expires_in if expires_in is not None else "unstated",
            )
            return token

    # --- subclass hooks -------------------------------------------------

    grant_description = "client_credentials"

    def _client_authentication(self) -> dict[str, str]:
        raise NotImplementedError

    # --- the request ----------------------------------------------------

    def _base_form(self) -> dict[str, str]:
        form = {"grant_type": "client_credentials", "client_id": self.client_id}
        if self.scope:
            form["scope"] = self.scope
        if self.audience:
            form["audience"] = self.audience
        return form

    async def _request_token(self, form: dict[str, str]) -> tuple[str, float | None]:
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=self._timeout
            ) as client:
                response = await client.post(self.token_endpoint, data=form)
        except httpx.HTTPError as exc:
            raise CredentialError(
                f"Credential {self.name!r}: token endpoint {self.token_endpoint} "
                f"could not be reached: {exc}"
            ) from exc
        return self._read_token_response(response)

    def _read_token_response(self, response: httpx.Response) -> tuple[str, float | None]:
        if response.status_code != 200:
            # The body of an OAuth error is a machine-readable error code, not
            # a credential, so it is safe and useful to report.
            raise CredentialError(
                f"Credential {self.name!r}: token endpoint "
                f"{self.token_endpoint} refused the request "
                f"(HTTP {response.status_code}): {response.text[:200]}"
            )
        try:
            payload: Any = response.json()
        except ValueError as exc:
            raise CredentialError(
                f"Credential {self.name!r}: token endpoint response was not JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise CredentialError(
                f"Credential {self.name!r}: token endpoint response was not a JSON object"
            )
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise CredentialError(
                f"Credential {self.name!r}: token endpoint response carried no "
                "'access_token'"
            )
        token_type = payload.get("token_type", "Bearer")
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            # The token is presented as a bearer; anything else would need a
            # different presentation (e.g. DPoP) and must not be guessed at.
            raise CredentialError(
                f"Credential {self.name!r}: unsupported token_type {token_type!r}; "
                "only 'Bearer' is presented"
            )
        expires_in = payload.get("expires_in")
        if isinstance(expires_in, bool) or not isinstance(expires_in, (int, float)):
            expires_in = None
        return token, float(expires_in) if expires_in is not None else None


class ClientCredentialsOAuthProvider(_TokenEndpointProvider):
    """``client_credentials`` with a client secret taken from the environment.

    The secret is read at acquisition time, not at construction, so rotating
    it is a restart of the process that holds the environment rather than a
    code path of its own — and so an unset variable is reported when it
    matters.
    """

    grant_description = GRANT_CLIENT_CREDENTIALS

    def __init__(self, *, client_secret_env: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.client_secret_env = client_secret_env

    def _client_authentication(self) -> dict[str, str]:
        secret = os.environ.get(self.client_secret_env)
        if not secret:
            raise CredentialError(
                f"Credential {self.name!r}: environment variable "
                f"{self.client_secret_env!r} is unset or empty, so the client "
                "secret for the client_credentials grant is not available"
            )
        return {"client_secret": secret}


class PrivateKeyJWTOAuthProvider(_TokenEndpointProvider):
    """``private_key_jwt`` client authentication (RFC 7523 §2.2).

    Signs a single-use assertion per acquisition: ``iss`` and ``sub`` are the
    client id, ``aud`` is the token endpoint (which is what stops an
    assertion captured by one authorization server being replayed at
    another), ``jti`` is fresh, and it expires in a minute.

    ``joserfc`` and ``cryptography`` are optional; install via ``pip install
    'extensible-mcp[oauth]'`` (or ``uv sync --group dev``). They are imported
    lazily so that a deployment using only ``client_credentials`` needs
    neither.
    """

    grant_description = GRANT_PRIVATE_KEY_JWT

    def __init__(self, *, private_key_file: Path, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.private_key_file = Path(private_key_file)
        self._key: Any | None = None
        self._alg: str | None = None

    def _load_key(self) -> tuple[Any, str]:
        if self._key is not None and self._alg is not None:
            return self._key, self._alg
        try:
            from cryptography.hazmat.primitives.asymmetric import ec, rsa
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key,
            )
            from joserfc.jwk import ECKey, RSAKey
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise CredentialError(
                f"Credential {self.name!r}: the private_key_jwt grant needs "
                "joserfc and cryptography. Install them with: pip install "
                "'extensible-mcp[oauth]' (or uv sync --group dev)"
            ) from exc

        try:
            pem = self.private_key_file.read_bytes()
        except OSError as exc:
            raise CredentialError(
                f"Credential {self.name!r}: cannot read private_key_file "
                f"{self.private_key_file}: {exc}"
            ) from exc
        try:
            loaded = load_pem_private_key(pem, password=None)
        except (ValueError, TypeError) as exc:
            raise CredentialError(
                f"Credential {self.name!r}: {self.private_key_file} is not a "
                f"readable unencrypted PEM private key: {exc}"
            ) from exc

        if isinstance(loaded, rsa.RSAPrivateKey):
            key: Any = RSAKey.import_key(pem)
            alg = "RS256"
        elif isinstance(loaded, ec.EllipticCurvePrivateKey):
            alg_name = _EC_ALGORITHMS.get(loaded.curve.name)
            if alg_name is None:
                raise CredentialError(
                    f"Credential {self.name!r}: EC curve {loaded.curve.name!r} is "
                    "not supported for a client assertion; use P-256, P-384 or P-521"
                )
            key = ECKey.import_key(pem)
            alg = alg_name
        else:
            raise CredentialError(
                f"Credential {self.name!r}: private_key_jwt supports RSA and EC "
                f"keys; {self.private_key_file} holds a "
                f"{type(loaded).__name__}"
            )
        self._key, self._alg = key, alg
        return key, alg

    def _assertion(self) -> str:
        from joserfc import jwt

        key, alg = self._load_key()
        now = int(time.time())
        claims = {
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": self.token_endpoint,
            "jti": secrets.token_urlsafe(16),
            "iat": now,
            "exp": now + ASSERTION_LIFETIME_SECONDS,
        }
        return jwt.encode({"alg": alg, "typ": "JWT"}, claims, key, algorithms=[alg])

    def _client_authentication(self) -> dict[str, str]:
        return {
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": self._assertion(),
        }


def build_provider(
    credential: CredentialConfig,
    *,
    scope: str | None = None,
    audience: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> CredentialProvider:
    """The provider for one (credential, server) pair.

    One per server rather than one per credential, because ``scope`` and
    ``audience`` differ per server and a token issued for one audience is not
    the token for another -- so the cache has to be keyed the same way.
    """
    common: dict[str, Any] = {
        "name": credential.name,
        "token_endpoint": credential.token_endpoint,
        "client_id": credential.client_id,
        "scope": scope,
        "audience": audience,
        "transport": transport,
    }
    if credential.grant == GRANT_PRIVATE_KEY_JWT:
        if credential.private_key_file is None:
            raise CredentialError(
                f"Credential {credential.name!r}: the private_key_jwt grant "
                "needs 'private_key_file'"
            )
        return PrivateKeyJWTOAuthProvider(
            private_key_file=credential.private_key_file, **common
        )
    if credential.grant == GRANT_CLIENT_CREDENTIALS:
        if not credential.client_secret_env:
            raise CredentialError(
                f"Credential {credential.name!r}: the client_credentials grant "
                "needs 'client_secret_env'"
            )
        return ClientCredentialsOAuthProvider(
            client_secret_env=credential.client_secret_env, **common
        )
    # Fail closed on a grant this build does not implement -- including one a
    # newer config knows about (a workload identity, say) and this proxy does
    # not. Guessing a grant would present the wrong credential.
    raise CredentialError(
        f"Credential {credential.name!r}: unsupported grant {credential.grant!r}; "
        f"this build implements {', '.join(SUPPORTED_GRANTS)}"
    )


class OAuthGrantAuth(httpx.Auth):
    """Presents a provider's token, and refreshes it once on a refusal.

    An ``httpx.Auth`` rather than a header fixed at client construction: the
    token is resolved per request, so a token acquired after the client was
    built, or re-acquired after a 401, needs no new client. The retry is
    bounded at one — a second refusal is the authorization server and the
    resource server disagreeing, which another token will not fix.
    """

    def __init__(
        self, provider: CredentialProvider, principal: ProxyItself = PROXY_ITSELF
    ) -> None:
        self._provider = provider
        self._principal = principal

    async def async_auth_flow(self, request: httpx.Request):  # type: ignore[override]
        request.headers["Authorization"] = (
            f"Bearer {await self._provider.token(self._principal)}"
        )
        response = yield request
        if response.status_code not in (401, 403):
            return
        logger.info(
            "Downstream refused the token (HTTP %s); re-acquiring and retrying once",
            response.status_code,
        )
        token = await self._provider.token(self._principal, force_refresh=True)
        request.headers["Authorization"] = f"Bearer {token}"
        yield request

    def sync_auth_flow(self, request: httpx.Request):  # type: ignore[override]
        # Acquisition is async; there is no synchronous path through the proxy.
        raise RuntimeError(
            "OAuthGrantAuth is async-only; use an httpx.AsyncClient"
        )

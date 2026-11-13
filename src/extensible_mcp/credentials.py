# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Downstream credentials acquired by an OAuth grant rather than read off disk.

A token in ``tokens_file`` is a long-lived bearer at rest: whoever reads the
file holds the credential until someone notices. This module replaces it with
an acquisition: the proxy authenticates itself to an authorization server and
is handed a short-lived access token, which lives only in memory.

Three grants ship. Two of them are RFC 6749 ``client_credentials`` at the
token endpoint, differing in how the proxy authenticates *as a client*:

- ``private_key_jwt`` (RFC 7523 §2.2) — the proxy signs a short-lived
  assertion with a private key the authorization server never sees. Nothing
  replayable is transmitted, so the credential cannot be harvested from
  traffic or logs.
- ``client_credentials`` — a client secret read from the environment. It
  relocates the liability rather than retiring it (a long-lived secret is
  still a secret), and ships because it is what most authorization servers
  are actually configured for.

The third, ``token_exchange`` (RFC 8693), is a different identity rather
than a different proof: the proxy presents the *caller's* inbound access
token as the ``subject_token`` and is handed a token the authorization
server issued for that caller, with the proxy as the client it was issued
to. The downstream then sees the person, not the proxy. See
:class:`TokenExchangeProvider` for what that does and does not promise.

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

:meth:`CredentialProvider.token` takes a principal, and there are two kinds:

- :data:`PROXY_ITSELF` -- the proxy's **service identity**. The credential is
  a property of the process: every caller shares one downstream identity,
  and per-caller authorization is the proxy's filters' job. The two
  ``client_credentials`` grants accept only this.
- a :class:`SubjectToken` -- the **delegated identity**: the caller's own
  verified inbound token, which the ``token_exchange`` grant exchanges for a
  downstream token about that caller. The service-identity grants refuse it,
  and the exchange grant accepts the proxy itself only for the one thing no
  caller is behind, listing a server's tools at admission.

A provider rejects a principal it does not serve rather than quietly treating
it as the proxy: the wrong identity downstream is the confused deputy, and a
refusal is the fail-closed outcome.
"""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, runtime_checkable

import httpx
import httpx2

from .types import CredentialConfig

logger = logging.getLogger(__name__)

GRANT_PRIVATE_KEY_JWT: Final = "private_key_jwt"
GRANT_CLIENT_CREDENTIALS: Final = "client_credentials"
GRANT_TOKEN_EXCHANGE: Final = "token_exchange"
#: The grants with working implementations. A grant outside this set is
#: refused at config load rather than ignored.
SUPPORTED_GRANTS: Final = (GRANT_PRIVATE_KEY_JWT, GRANT_CLIENT_CREDENTIALS, GRANT_TOKEN_EXCHANGE)
#: The grants that acquire the proxy's own service identity. The remaining
#: one, ``token_exchange``, acquires a token about the caller.
SERVICE_IDENTITY_GRANTS: Final = (GRANT_PRIVATE_KEY_JWT, GRANT_CLIENT_CREDENTIALS)

CLIENT_ASSERTION_TYPE: Final = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
TOKEN_EXCHANGE_GRANT_TYPE: Final = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE: Final = "urn:ietf:params:oauth:token-type:access_token"

#: How many callers' exchanged tokens one provider keeps. Past this the
#: least recently used is dropped and re-exchanged on its next call; a bound
#: because the set of callers is open and the process is long-lived.
EXCHANGE_CACHE_SIZE: Final = 1024

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
    """The type of the proxy's own service identity, as a principal a
    credential is acquired for.

    Deliberately not the :class:`~extensible_mcp.types.Principal` of a
    caller: that is a fact about a person and never a credential, and the
    caller's side of this seam is :class:`SubjectToken`. This is a sentinel
    type with a single instance, :data:`PROXY_ITSELF`.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "PROXY_ITSELF"


#: The proxy's own service identity, the principal every grant accepts for
#: the proxy acting as itself.
PROXY_ITSELF: Final = ProxyItself()


@dataclass(frozen=True, eq=False, repr=False)
class SubjectToken:
    """The caller's verified inbound access token, as the subject of an
    exchange.

    Built by the server at dispatch, *after* the call pipeline allowed the
    call, from the token FastMCP verified on the request, and handed only to
    the client manager; no filter, fetch-plan source or response filter ever
    sees it. The :class:`~extensible_mcp.types.Principal` stays a fact about
    identity and never carries the token, which is why this is a second
    type and not a field on it.

    ``value`` is a bearer and is treated as one: never logged, never
    compared, never put in a message. ``repr`` shows the issuer and subject
    only, and equality is identity, so two tokens for one person are not
    "equal" anywhere a set or a dict might deduplicate them.
    ``expires_at`` is the token's own expiry as epoch seconds, or ``None``
    when the verifier reported none; an exchanged token never outlives it.
    """

    value: str
    iss: str
    sub: str
    expires_at: float | None = None

    def __repr__(self) -> str:
        return f"SubjectToken(iss={self.iss!r}, sub={self.sub!r})"

    __str__ = __repr__


#: What a provider may be asked for a token for.
CredentialPrincipal = ProxyItself | SubjectToken


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

    async def token(self, principal: CredentialPrincipal, *, force_refresh: bool = False) -> str:
        ...


def _require_proxy_principal(principal: object) -> None:
    if principal is not PROXY_ITSELF:
        raise CredentialError(
            f"Unsupported principal {principal!r}: this credential is the proxy's "
            "own service identity and is acquired only for the proxy itself "
            "(extensible_mcp.credentials.PROXY_ITSELF). A credential about the "
            "caller is the token_exchange grant."
        )


def _require_subject(principal: object, name: str) -> SubjectToken:
    if not isinstance(principal, SubjectToken):
        raise CredentialError(
            f"Credential {name!r} uses the token_exchange grant, which presents "
            f"the caller's delegated token, and {principal!r} is not a caller's "
            "token. The proxy never substitutes its own identity for a caller's."
        )
    return principal


class _TokenEndpointProvider:
    """Shared machinery for the two shipping grants.

    Caches the acquired token until shortly before its stated expiry, and
    serializes acquisition so a burst of concurrent calls makes one token
    request rather than one each. Subclasses supply the client
    authentication half of the form body.

    ``per_caller`` says whether the token the provider serves on a call is
    about the caller (``token_exchange``) or the proxy (the rest). The
    client manager reads it to decide what a call must carry.
    """

    per_caller: bool = False

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

    async def token(self, principal: CredentialPrincipal, *, force_refresh: bool = False) -> str:
        _require_proxy_principal(principal)
        return await self._service_token(force_refresh=force_refresh)

    async def _service_token(self, *, force_refresh: bool = False) -> str:
        """The proxy's own token, cached process-wide."""
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
        return _client_secret_form(self.name, self.client_secret_env)


def _client_secret_form(name: str, client_secret_env: str) -> dict[str, str]:
    """The client-secret half of a token request, read from the environment
    at acquisition time."""
    secret = os.environ.get(client_secret_env)
    if not secret:
        raise CredentialError(
            f"Credential {name!r}: environment variable "
            f"{client_secret_env!r} is unset or empty, so the client "
            "secret is not available"
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
        self._signer = _AssertionSigner(
            name=self.name,
            client_id=self.client_id,
            token_endpoint=self.token_endpoint,
            private_key_file=self.private_key_file,
        )

    def _load_key(self) -> tuple[Any, str]:
        return self._signer.load_key()

    def _assertion(self) -> str:
        return self._signer.assertion()

    def _client_authentication(self) -> dict[str, str]:
        return self._signer.form()


class _AssertionSigner:
    """The ``private_key_jwt`` half of a token request: the key, loaded
    once, and a fresh single-use assertion per acquisition. Shared by the
    grant of that name and by ``token_exchange`` authenticating the same
    way."""

    def __init__(
        self, *, name: str, client_id: str, token_endpoint: str, private_key_file: Path
    ) -> None:
        self.name = name
        self.client_id = client_id
        self.token_endpoint = token_endpoint
        self.private_key_file = Path(private_key_file)
        self._key: Any | None = None
        self._alg: str | None = None

    def load_key(self) -> tuple[Any, str]:
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

    def assertion(self) -> str:
        from joserfc import jwt

        key, alg = self.load_key()
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

    def form(self) -> dict[str, str]:
        return {
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": self.assertion(),
        }


class _Exchanged:
    """One caller's exchanged token: the value, when it stops being served,
    and when it was acquired."""

    __slots__ = ("token", "expires_at", "acquired_at")

    def __init__(self, token: str, expires_at: float | None, acquired_at: float) -> None:
        self.token = token
        self.expires_at = expires_at
        self.acquired_at = acquired_at

    def usable(self) -> bool:
        if self.expires_at is None:
            return True
        return time.monotonic() < self.expires_at - EXPIRY_SKEW_SECONDS


class TokenExchangeProvider(_TokenEndpointProvider):
    """RFC 8693 token exchange: a downstream token about the **caller**.

    Given a :class:`SubjectToken`, the proxy sends it as ``subject_token``
    with its own client authentication (a signed assertion or a client
    secret, exactly one configured) and is handed a token the authorization
    server issued for that caller, with the proxy as the client it was issued
    to. What the downstream sees is therefore the person as ``sub`` and the
    proxy as ``azp``, plus ``act`` wherever the authorization server asserts
    delegation (Keycloak's standard exchange does not; its delegation flow is
    a separate preview feature). No ``actor_token`` is sent: the client
    authentication *is* the actor, and a delegation claim is the server's to
    assert, never the proxy's to request.

    **Never a fallback.** A caller's exchange that fails fails the call; the
    provider does not substitute the proxy's own identity. The proxy's own
    token is served for :data:`PROXY_ITSELF` only, which the client manager
    asks for only to list a server's tools at admission, where no caller
    exists. A call always comes with its caller.

    **The cache** is per caller, keyed by the subject token's ``iss`` and
    ``sub``, bounded to ``cache_size`` entries with least-recently-used
    eviction, and an entry lives for the exchanged token's ``expires_in``
    capped by the subject token's own expiry, so a delegated token never
    outlives the session it was exchanged from. One lock per key: a burst
    from one caller exchanges once, and two callers exchange concurrently.
    """

    grant_description = GRANT_TOKEN_EXCHANGE
    per_caller = True

    def __init__(
        self,
        *,
        private_key_file: Path | None = None,
        client_secret_env: str | None = None,
        cache_size: int = EXCHANGE_CACHE_SIZE,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        if (private_key_file is None) == (client_secret_env is None):
            raise CredentialError(
                f"Credential {self.name!r}: the token_exchange grant authenticates "
                "the proxy with exactly one of 'private_key_file' or "
                "'client_secret_env'"
            )
        self.private_key_file = Path(private_key_file) if private_key_file else None
        self.client_secret_env = client_secret_env
        self._signer = (
            _AssertionSigner(
                name=self.name,
                client_id=self.client_id,
                token_endpoint=self.token_endpoint,
                private_key_file=self.private_key_file,
            )
            if self.private_key_file is not None
            else None
        )
        if cache_size < 1:
            raise CredentialError(
                f"Credential {self.name!r}: cache_size must be at least 1"
            )
        self._cache_size = cache_size
        self._exchanged: OrderedDict[tuple[str, str], _Exchanged] = OrderedDict()
        self._locks: dict[tuple[str, str], asyncio.Lock] = {}

    def _client_authentication(self) -> dict[str, str]:
        if self._signer is not None:
            return self._signer.form()
        assert self.client_secret_env is not None
        return _client_secret_form(self.name, self.client_secret_env)

    @property
    def cached_callers(self) -> int:
        """How many callers' exchanged tokens are held, for tests and logs."""
        return len(self._exchanged)

    async def token(self, principal: CredentialPrincipal, *, force_refresh: bool = False) -> str:
        if principal is PROXY_ITSELF:
            # The proxy as itself: the one use is listing a server's tools at
            # admission, where no caller is behind the request.
            return await self._service_token(force_refresh=force_refresh)
        subject = _require_subject(principal, self.name)
        key = (subject.iss, subject.sub)
        lock = self._locks.get(key)
        if lock is None:
            lock = self._locks[key] = asyncio.Lock()
        async with lock:
            if force_refresh:
                self._exchanged.pop(key, None)
            entry = self._exchanged.get(key)
            if entry is not None and entry.usable():
                self._exchanged.move_to_end(key)
                return entry.token
            self._exchanged.pop(key, None)
            form = self._exchange_form(subject)
            form.update(self._client_authentication())
            token, expires_in = await self._request_token(form)
            now = time.monotonic()
            expires_at = now + expires_in if expires_in is not None else None
            if subject.expires_at is not None:
                # Never past the session it was exchanged from.
                subject_remaining = subject.expires_at - time.time()
                cap = now + max(subject_remaining, 0.0)
                expires_at = cap if expires_at is None else min(expires_at, cap)
            self._exchanged[key] = _Exchanged(token, expires_at, now)
            self._acquired_at = now
            self._evict()
            logger.info(
                "Exchanged the caller's token for a downstream token via credential "
                "%r (expires_in=%s, callers cached=%d)",
                self.name,
                expires_in if expires_in is not None else "unstated",
                len(self._exchanged),
            )
            return token

    def _exchange_form(self, subject: SubjectToken) -> dict[str, str]:
        form = {
            "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
            "client_id": self.client_id,
            "subject_token": subject.value,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "requested_token_type": ACCESS_TOKEN_TYPE,
        }
        if self.scope:
            form["scope"] = self.scope
        if self.audience:
            form["audience"] = self.audience
        return form

    def _read_token_response(self, response: httpx.Response) -> tuple[str, float | None]:
        token, expires_in = super()._read_token_response(response)
        issued = response.json().get("issued_token_type")
        if issued is not None and issued != ACCESS_TOKEN_TYPE:
            # RFC 8693 §2.2.1: the server says what it issued. Anything but
            # an access token would be presented as one and refused.
            raise CredentialError(
                f"Credential {self.name!r}: token endpoint issued "
                f"{issued!r}; only an access token is presented downstream"
            )
        return token, expires_in

    def _evict(self) -> None:
        """Drop expired entries, then the least recently used past the bound."""
        for key in [k for k, e in self._exchanged.items() if not e.usable()]:
            del self._exchanged[key]
            self._locks.pop(key, None)
        while len(self._exchanged) > self._cache_size:
            key, _ = self._exchanged.popitem(last=False)
            self._locks.pop(key, None)


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
    if credential.grant == GRANT_TOKEN_EXCHANGE:
        return TokenExchangeProvider(
            private_key_file=credential.private_key_file,
            client_secret_env=credential.client_secret_env,
            **common,
        )
    # Fail closed on a grant this build does not implement -- including one a
    # newer config knows about (a workload identity, say) and this proxy does
    # not. Guessing a grant would present the wrong credential.
    raise CredentialError(
        f"Credential {credential.name!r}: unsupported grant {credential.grant!r}; "
        f"this build implements {', '.join(SUPPORTED_GRANTS)}"
    )


class OAuthGrantAuth(httpx2.Auth):
    """Presents a provider's token, and refreshes it once on a refusal.

    An ``httpx2.Auth`` -- the MCP SDK's streamable transport is built on
    httpx2, so the client it is given must be one, while the token endpoint
    behind the provider is reached with httpx and is none of the
    transport's business -- rather than a header fixed at client construction: the
    token is resolved per request, so a token acquired after the client was
    built, or re-acquired after a 401, needs no new client. The retry is
    bounded at one — a second refusal is the authorization server and the
    resource server disagreeing, which another token will not fix.
    """

    def __init__(
        self, provider: CredentialProvider, principal: CredentialPrincipal = PROXY_ITSELF
    ) -> None:
        self._provider = provider
        self._principal = principal

    async def async_auth_flow(self, request: httpx2.Request):  # type: ignore[override]
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
        response = yield request
        # A second refusal is final, and it must reach the caller *as* a
        # refusal. SDK 2's transport folds any non-2xx status into a generic
        # JSON-RPC error with the status gone, so the proxy could no longer
        # tell "the credential was rejected" from "the server fell over";
        # raising here keeps the 401/403 on the exception, where
        # ClientManager translates it into TokenExpiredError.
        if response.status_code in (401, 403):
            response.raise_for_status()

    def sync_auth_flow(self, request: httpx2.Request):  # type: ignore[override]
        # Acquisition is async; there is no synchronous path through the proxy.
        raise RuntimeError(
            "OAuthGrantAuth is async-only; use an httpx2.AsyncClient"
        )

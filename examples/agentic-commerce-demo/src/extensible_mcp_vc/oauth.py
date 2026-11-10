# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""A minimal OAuth 2.0 authorization server, so enrollment has an identity.

The approval service holds the household admin's private key and will sign
"this passkey holds role *parent*" for whatever a caller asks. Until this
module existed the only gate was reaching the page, which is trusting an
actor by virtue of where it sits — the posture this project rejects. What the
enrollment surface needs is an *identity*, because role has to be derived
from who you are rather than taken from the request body.

**Why a real flow and not a password check.** Authorization code + PKCE is
what an external identity provider speaks. Building the demo against that
shape keeps a later swap to Entra, Keycloak, Okta or Auth0 a bounded change
to this module rather than a redesign of the page. That swap is now a
configuration step: with ``APPROVAL_ISSUER`` set the service runs in
**external-issuer mode** (:class:`ExternalIssuer`), where the realm's tokens
are verified with the same ``JWTVerifier`` the proxy's ``auth`` block builds,
``/authorize`` redirects to the provider and ``/token`` forwards the code
exchange, and the page is unchanged. One mode per process: in external mode
a token this server minted is refused like any other. The resource-owner
password grant would have been a third of the code and is deprecated in
OAuth 2.1 — and choosing it would have thrown away the one property that
makes this worth doing.

**Why the passwords are random.** They are generated per workspace and
printed at startup. A fixed pair like "parent"/"child" would make the login a
speed bump rather than a control: anything that can reach the service guesses
it in two tries, and a visible login that is not a gate is worse than none,
because it stops a reader asking. Random credentials in a file only the
operator can read make this an actual boundary while keeping the demo a
one-command affair.

**What a real deployment does differently.** It does not store passwords at
all — it delegates to an IdP, and users arrive with a token this service only
has to verify. The plaintext file here exists so the demo can print the
credentials to its own log; it is a demo affordance, and the honest reason it
is acceptable is that these credentials guard a mock pizza purchase.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlencode

import httpx2
from joserfc import jwt
from joserfc.jwk import OctKey

ISSUER = "https://approval.demo.invalid"
AUDIENCE = "approval-service"
CLIENT_ID = "approval-page"
#: The chat console's own client at the organization's identity provider,
#: and the audience the family proxy verifies. One client per browser
#: surface and one audience per resource server: a token for the passkey
#: page is never a token for the proxy, nor the reverse.
CONSOLE_CLIENT_ID = "family-console"
PROXY_AUDIENCE = "family-proxy"

#: The two roles an enrollment can be made under, and the claim an external
#: issuer carries them in (a list, since one person can hold both). The
#: committed Keycloak realm's role mapper emits exactly this claim with
#: exactly these values; ``tests/test_keycloak_realm.py`` holds it to that.
ROLES: Final = ("child", "parent")
ROLES_CLAIM: Final = "roles"
#: RFC 8176 authentication-method values an enrollment requires in external
#: mode, by default: ``hwk`` is proof of possession of a hardware-secured
#: key, which is what the realm's passwordless flow records. Enrollment is
#: the first link of the evidence chain, so a password sign-in at the
#: provider does not get to enrol a passkey. ``APPROVAL_REQUIRED_AMR``
#: overrides it (comma-separated; empty disables the check).
DEFAULT_REQUIRED_AMR: Final = frozenset({"hwk"})

# An authorization code is redeemed immediately by the page, so it lives for
# seconds. The access token has to outlast a human deciding whether to
# approve a pizza.
CODE_TTL_SECONDS = 60
TOKEN_TTL_SECONDS = 3600

_PASSWORD_BYTES = 12  # ~96 bits, printed as base64url


class OAuthError(Exception):
    """A protocol or credential failure. Carries an OAuth 2.0 error code."""

    def __init__(self, code: str, description: str) -> None:
        super().__init__(f"{code}: {description}")
        self.code = code
        self.description = description


def _b64url_nopad(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def pkce_challenge(verifier: str) -> str:
    """The S256 challenge for a verifier, as the client computes it."""
    return _b64url_nopad(hashlib.sha256(verifier.encode()).digest())


@dataclass
class DemoUser:
    username: str
    password: str
    role: str


class DemoUserStore:
    """The two demo identities, with passwords generated once per workspace.

    Persisted so a restart does not invalidate the credentials a human has
    already been shown, and so the manual walkthrough and the containerized
    run agree -- and so they can be read back after the startup line has
    scrolled away. Written 0600; a real deployment has no equivalent file.
    """

    FILENAME = "approval-users.json"

    def __init__(self, workspace: Path, roles: tuple[str, ...] = ("child", "parent")) -> None:
        self.path = workspace / self.FILENAME
        self._users: dict[str, DemoUser] = {}
        self._load_or_create(roles)

    def _load_or_create(self, roles: tuple[str, ...]) -> None:
        if self.path.exists():
            raw = json.loads(self.path.read_text())
            for name, rec in raw.get("users", {}).items():
                self._users[name] = DemoUser(name, rec["password"], rec["role"])
            if set(self._users) == set(roles):
                return
            # Roles changed under us; regenerate rather than half-honour a
            # stale file.
            self._users.clear()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for role in roles:
            self._users[role] = DemoUser(role, secrets.token_urlsafe(_PASSWORD_BYTES), role)
        self.path.write_text(
            json.dumps(
                {"users": {u.username: {"password": u.password, "role": u.role}
                           for u in self._users.values()}},
                indent=2,
            )
            + "\n"
        )
        os.chmod(self.path, 0o600)

    def authenticate(self, username: str, password: str) -> DemoUser:
        user = self._users.get(username)
        # compare_digest on a placeholder when the user is unknown, so a bad
        # username and a bad password take the same time.
        expected = user.password if user is not None else "\x00" * 32
        ok = secrets.compare_digest(password, expected)
        if user is None or not ok:
            raise OAuthError("invalid_grant", "unknown username or wrong password")
        return user

    @property
    def users(self) -> list[DemoUser]:
        return sorted(self._users.values(), key=lambda u: u.username)

    def banner(self) -> str:
        """The line printed at startup so a human can sign in."""
        creds = "  ".join(f"{u.username}/{u.password}" for u in self.users)
        return f"[approval] sign-in credentials (this workspace): {creds}"


@dataclass
class _PendingCode:
    sub: str
    role: str
    challenge: str
    redirect_uri: str
    expires_at: float


@dataclass
class AuthorizationServer:
    """Authorization code + PKCE, with an HS256 access token.

    The signing secret is per process, so a restart invalidates outstanding
    tokens — correct for a demo, and it keeps the secret off disk.
    """

    users: DemoUserStore
    allowed_redirect_uris: tuple[str, ...] = ("/",)
    clock: Any = time.time
    _secret: OctKey = field(
        default_factory=lambda: OctKey.import_key(secrets.token_bytes(32))
    )
    _codes: dict[str, _PendingCode] = field(default_factory=dict)

    # -- authorization endpoint --------------------------------------------- #

    def validate_authorization_request(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        response_type: str,
        code_challenge: str,
        code_challenge_method: str,
    ) -> None:
        """Check everything that must be right before showing a login form.

        The redirect_uri is validated against an allowlist rather than echoed
        back: an authorization server that redirects anywhere the request names
        is an open redirect, and hands codes to whoever asked.
        """
        if client_id != CLIENT_ID:
            raise OAuthError("unauthorized_client", f"unknown client_id {client_id!r}")
        if redirect_uri not in self.allowed_redirect_uris:
            raise OAuthError("invalid_request", "redirect_uri is not registered")
        if response_type != "code":
            raise OAuthError("unsupported_response_type", "only 'code' is supported")
        if code_challenge_method != "S256":
            raise OAuthError(
                "invalid_request", "only the S256 code_challenge_method is supported"
            )
        if not code_challenge:
            raise OAuthError("invalid_request", "code_challenge is required (PKCE)")

    def issue_code(
        self, *, username: str, password: str, redirect_uri: str, code_challenge: str
    ) -> str:
        user = self.users.authenticate(username, password)
        self._prune()
        code = secrets.token_urlsafe(24)
        self._codes[code] = _PendingCode(
            sub=user.username,
            role=user.role,
            challenge=code_challenge,
            redirect_uri=redirect_uri,
            expires_at=self.clock() + CODE_TTL_SECONDS,
        )
        return code

    # -- token endpoint ----------------------------------------------------- #

    def exchange_code(
        self, *, code: str, code_verifier: str, redirect_uri: str, client_id: str
    ) -> dict[str, Any]:
        self._prune()
        # Single-use: popped before anything can fail, so a rejected exchange
        # cannot be retried against the same code.
        pending = self._codes.pop(code, None)
        if pending is None:
            raise OAuthError("invalid_grant", "unknown, expired or already-used code")
        if client_id != CLIENT_ID:
            raise OAuthError("unauthorized_client", "client_id does not match")
        if redirect_uri != pending.redirect_uri:
            raise OAuthError("invalid_grant", "redirect_uri does not match the request")
        if not secrets.compare_digest(pkce_challenge(code_verifier), pending.challenge):
            raise OAuthError("invalid_grant", "code_verifier does not match the challenge")
        return {
            "access_token": self._mint_token(pending.sub, pending.role),
            "token_type": "Bearer",
            "expires_in": TOKEN_TTL_SECONDS,
            "scope": "enroll approve",
        }

    def _mint_token(self, sub: str, role: str) -> str:
        now = int(self.clock())
        return jwt.encode(
            {"alg": "HS256", "typ": "JWT"},
            {
                "iss": ISSUER,
                "aud": AUDIENCE,
                "sub": sub,
                "role": role,
                "iat": now,
                "exp": now + TOKEN_TTL_SECONDS,
                "jti": secrets.token_urlsafe(12),
            },
            self._secret,
        )

    # -- resource server side ---------------------------------------------- #

    def verify_token(self, authorization_header: str | None) -> dict[str, Any]:
        """Claims for a valid `Authorization: Bearer <jwt>`, else OAuthError.

        Every failure is `invalid_token` with no detail about which check
        failed — a caller holding a bad token learns nothing from probing.
        """
        if not authorization_header or not authorization_header.startswith("Bearer "):
            raise OAuthError("invalid_token", "a bearer token is required")
        token = authorization_header[7:].strip()
        try:
            decoded = jwt.decode(token, self._secret, algorithms=["HS256"])
        except Exception as e:  # noqa: BLE001 - any JOSE failure is one refusal
            raise OAuthError("invalid_token", "token could not be verified") from e
        claims = decoded.claims
        now = self.clock()
        if claims.get("iss") != ISSUER or claims.get("aud") != AUDIENCE:
            raise OAuthError("invalid_token", "token was not issued for this service")
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)) or exp <= now:
            raise OAuthError("invalid_token", "token has expired")
        if not isinstance(claims.get("role"), str) or not claims["role"]:
            raise OAuthError("invalid_token", "token carries no role")
        return claims

    def _prune(self) -> None:
        now = self.clock()
        for code in [c for c, p in self._codes.items() if p.expires_at <= now]:
            del self._codes[code]


# -- roles, in both modes ---------------------------------------------------- #


def roles_of(claims: Mapping[str, Any]) -> list[str]:
    """The roles a token asserts: the ``roles`` list, or the single ``role``
    string this server's own tokens carry, read as a one-element list."""
    raw = claims.get(ROLES_CLAIM)
    if raw is None:
        single = claims.get("role")
        raw = [single] if isinstance(single, str) else []
    elif isinstance(raw, str):
        raw = [raw]
    elif not isinstance(raw, list):
        raw = []
    return [r for r in raw if isinstance(r, str) and r]


def eligible_roles(claims: Mapping[str, Any]) -> list[str]:
    """The enrollable roles the token holds, in vocabulary order."""
    held = roles_of(claims)
    return [r for r in ROLES if r in held]


def select_role(claims: Mapping[str, Any], requested: str | None) -> str:
    """The role an enrollment is made under: derived from the token, never
    asserted by the request.

    One eligible role means that role, and ``requested`` is ignored, as it
    always was. Two means the request must select one of them -- the body
    picks between what the token already grants and can never widen it.
    None is a refusal.
    """
    eligible = eligible_roles(claims)
    if not eligible:
        raise OAuthError(
            "insufficient_scope",
            f"the token carries no enrollable role (needs one of {', '.join(ROLES)})",
        )
    if len(eligible) == 1:
        return eligible[0]
    if requested in eligible:
        return requested
    raise OAuthError(
        "invalid_request",
        f"the token carries {' and '.join(eligible)}; the request must select one",
    )


def check_amr(claims: Mapping[str, Any], required: frozenset[str]) -> None:
    """Refuse an enrollment whose sign-in did not use a required method."""
    if not required:
        return
    raw = claims.get("amr")
    held = {v for v in raw if isinstance(v, str)} if isinstance(raw, list) else set()
    if not held & required:
        raise OAuthError(
            "insufficient_scope",
            "enrollment requires an authentication method in "
            f"{{{', '.join(sorted(required))}}}; the token carries "
            f"{{{', '.join(sorted(held)) or 'none'}}}",
        )


# -- an external issuer ------------------------------------------------------ #


class ExternalIssuerError(Exception):
    """The identity provider could not be reached, or answered out of shape.

    A 503 at the service, never ``invalid_token``: the caller's token was not
    judged, so the caller must not be told it was bad.
    """


@dataclass(frozen=True)
class ExternalIssuerConfig:
    """External-issuer mode, from the environment.

    ``issuer`` is what the provider's tokens name in ``iss`` and where the
    browser is sent to sign in. ``internal_base`` is where *this service*
    reaches the provider, which differs inside a container: the browser
    reaches Keycloak at ``localhost:8080`` while the service reaches it at
    ``keycloak:8080``. URLs the provider publishes are rewritten from the one
    onto the other for the service's own requests only.
    """

    issuer: str
    internal_base: str
    audience: str = AUDIENCE
    client_id: str = CLIENT_ID
    jwks_uri: str | None = None
    required_amr: frozenset[str] = DEFAULT_REQUIRED_AMR

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> ExternalIssuerConfig | None:
        env = os.environ if environ is None else environ
        issuer = (env.get("APPROVAL_ISSUER") or "").strip().rstrip("/")
        if not issuer:
            return None
        internal = (env.get("APPROVAL_ISSUER_INTERNAL") or "").strip().rstrip("/") or issuer
        amr_raw = env.get("APPROVAL_REQUIRED_AMR")
        if amr_raw is None:
            required = DEFAULT_REQUIRED_AMR
        else:
            required = frozenset(v.strip() for v in amr_raw.split(",") if v.strip())
        return cls(
            issuer=issuer,
            internal_base=internal,
            jwks_uri=(env.get("APPROVAL_JWKS_URI") or "").strip() or None,
            required_amr=required,
        )

    def internal(self, url: str) -> str:
        """A provider-published URL, as this service reaches it."""
        if self.internal_base == self.issuer or not url.startswith(self.issuer):
            return url
        return self.internal_base + url[len(self.issuer):]


_DISCOVERY_KEYS: Final = ("authorization_endpoint", "token_endpoint", "jwks_uri")


class ExternalIssuer:
    """The provider side of external-issuer mode.

    Verifies the realm's tokens, sends the browser to the provider's
    authorize endpoint, and forwards the page's code exchange to the
    provider's token endpoint. The verifier is FastMCP's ``JWTVerifier``,
    constructed with the same arguments the proxy's ``auth`` block passes
    (issuer, audience, JWKS, RS256): one verifier in the repo, so the page
    and the proxy accept a token on the same terms.

    Discovery is lazy and cached: the service starts before the provider
    may be up, and nothing here retries on its behalf.
    """

    def __init__(
        self,
        config: ExternalIssuerConfig,
        *,
        http_client: httpx2.AsyncClient | None = None,
        verifier: Any | None = None,
    ) -> None:
        self.config = config
        self._http = http_client or httpx2.AsyncClient(timeout=httpx2.Timeout(10.0))
        self._verifier = verifier
        self._discovery: dict[str, Any] | None = None
        self._lock = asyncio.Lock()

    async def discovery(self) -> dict[str, Any]:
        if self._discovery is not None:
            return self._discovery
        async with self._lock:
            if self._discovery is not None:
                return self._discovery
            url = self.config.internal(self.config.issuer + "/.well-known/openid-configuration")
            try:
                response = await self._http.get(url)
            except httpx2.HTTPError as e:
                raise ExternalIssuerError(
                    f"identity provider {self.config.issuer} is unreachable: {e}"
                ) from e
            if response.status_code != 200:
                raise ExternalIssuerError(
                    f"identity provider discovery at {url} answered HTTP {response.status_code}"
                )
            try:
                doc = response.json()
            except ValueError as e:
                raise ExternalIssuerError("identity provider discovery was not JSON") from e
            if not isinstance(doc, dict) or doc.get("issuer") != self.config.issuer:
                raise ExternalIssuerError(
                    f"identity provider discovery names issuer {doc.get('issuer')!r}; "
                    f"configured {self.config.issuer!r}"
                )
            for key in _DISCOVERY_KEYS:
                if not isinstance(doc.get(key), str) or not doc[key]:
                    raise ExternalIssuerError(f"identity provider discovery lacks {key!r}")
            self._discovery = doc
            return doc

    async def verifier(self) -> Any:
        if self._verifier is None:
            from fastmcp.server.auth.providers.jwt import JWTVerifier

            jwks_uri = self.config.jwks_uri or (await self.discovery())["jwks_uri"]
            self._verifier = JWTVerifier(
                issuer=self.config.issuer,
                audience=self.config.audience,
                jwks_uri=self.config.internal(jwks_uri),
                algorithm="RS256",
                http_client=self._http,
            )
        return self._verifier

    async def verify_token(self, authorization_header: str | None) -> dict[str, Any]:
        """Claims for a valid bearer from the provider, else ``OAuthError``.

        The same one-refusal rule as the internal verifier: every failure is
        ``invalid_token`` with no detail. A provider that cannot be reached is
        :class:`ExternalIssuerError` instead, since no judgement was made.
        """
        if not authorization_header or not authorization_header.startswith("Bearer "):
            raise OAuthError("invalid_token", "a bearer token is required")
        token = authorization_header[7:].strip()
        verifier = await self.verifier()
        try:
            verified = await verifier.verify_token(token)
        except ExternalIssuerError:
            raise
        except Exception as e:  # noqa: BLE001 - any JOSE or fetch failure is one refusal
            raise OAuthError("invalid_token", "token could not be verified") from e
        if verified is None:
            raise OAuthError("invalid_token", "token could not be verified")
        claims = dict(getattr(verified, "claims", None) or {})
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise OAuthError("invalid_token", "token names nobody")
        return claims

    async def authorize_url(
        self, *, redirect_uri: str, code_challenge: str, state: str, fresh: bool = False
    ) -> str:
        """Where to send the browser: the provider's authorize endpoint, as
        published (the browser reaches the provider at the public issuer).

        ``fresh`` asks the provider to authenticate again (``prompt=login``)
        rather than reuse its session: the page needs that when its token
        was not produced by a passkey, since a silent re-issue from the same
        session would carry the same ``amr``.
        """
        endpoint = (await self.discovery())["authorization_endpoint"]
        query = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if state:
            query["state"] = state
        if fresh:
            query["prompt"] = "login"
        return endpoint + ("&" if "?" in endpoint else "?") + urlencode(query)

    async def exchange_code(
        self, *, code: str, code_verifier: str, redirect_uri: str, client_id: str
    ) -> tuple[int, Any]:
        """Forward the page's code exchange and return the provider's answer
        as is, status included. The PKCE verifier passes through; this
        service never holds a client secret, since the client is public."""
        if client_id != self.config.client_id:
            raise OAuthError("unauthorized_client", "client_id does not match")
        endpoint = self.config.internal((await self.discovery())["token_endpoint"])
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
        }
        try:
            response = await self._http.post(endpoint, data=form)
        except httpx2.HTTPError as e:
            raise ExternalIssuerError(
                f"identity provider token endpoint is unreachable: {e}"
            ) from e
        try:
            body = response.json()
        except ValueError as e:
            raise ExternalIssuerError("identity provider token endpoint did not answer JSON") from e
        return response.status_code, body


# -- the organization's accounts, bound into the memberships ----------------- #


def realm_user_ids(realm_path: Path) -> dict[str, str]:
    """``username -> id`` for the users the committed realm pins.

    Keycloak keeps a user's ``id`` on import when the file carries one, which
    is what lets the admin bind the organization's account into a membership
    credential *before* anyone has signed in. The ids are the realm file's;
    nothing here invents one.
    """
    realm = json.loads(Path(realm_path).read_text())
    out: dict[str, str] = {}
    for user in realm.get("users", []):
        uid, name = user.get("id"), user.get("username")
        if isinstance(uid, str) and uid and isinstance(name, str) and name:
            out[name] = uid
    return out


def bound_accounts(issuer: str, realm_path: Path) -> dict[str, list[tuple[str, str]]]:
    """The ``accounts`` each member's membership credential should carry
    when the demo runs on the organization's identity provider: the
    issuer, and the member's pinned account there, as ``(idp, account)``
    pairs keyed by username. The membership's ``accounts`` list is what the
    production bundles' ``account_bound`` check tests the console session
    against, so this is the admin saying which member each account is.
    """
    issuer = issuer.rstrip("/")
    return {name: [(issuer, uid)] for name, uid in realm_user_ids(realm_path).items()}

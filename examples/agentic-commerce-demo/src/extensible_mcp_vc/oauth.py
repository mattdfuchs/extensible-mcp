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
shape means replacing this module with Entra, Keycloak, Okta or Auth0 is a
matter of pointing at a different issuer, not a rewrite. The resource-owner
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

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from joserfc import jwt
from joserfc.jwk import OctKey

ISSUER = "https://approval.demo.invalid"
AUDIENCE = "approval-service"
CLIENT_ID = "approval-page"

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
    run agree. Written 0600; a real deployment has no equivalent file.
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

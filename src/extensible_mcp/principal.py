# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""From a verified inbound token to a :class:`~extensible_mcp.types.Principal`.

The proxy writes no verifier. FastMCP verifies the bearer on each HTTP
request against the configured ``AuthProvider`` and exposes the result
through ``get_access_token()``; this module turns that token's claims into
the one identity value every pipeline carries. Two things are decided here
and nowhere else:

- **Which claim holds the roles, and what its values mean.** The
  :class:`PrincipalMapping` names the claim by dotted path (``roles``, which
  is what the committed Keycloak realm's mapper emits; ``realm_access.roles``
  for a stock realm) and optionally maps its values. With no map the values
  are the deployment's own role names verbatim -- the identity case, so an
  issuer that already speaks our vocabulary needs no translation layer in
  front of it. With a map, the map is total: a value it does not name is
  dropped and logged once, never passed through.
- **That the principal is a fact, not a credential.** Only the fields the
  :class:`Principal` declares are read; the token itself never leaves
  FastMCP's request scope.

:func:`build_auth_provider` is the config form: an ``auth`` block builds a
``JWTVerifier`` -- issuer, audience, a JWKS URI or a public key -- and
nothing else. That is resource-server mode, where the token was issued to
the client by an external authorization server with the proxy as its
audience. An ``OIDCProxy``, which fronts an identity provider and mints its
own tokens, is an embedder's choice through ``create_server(auth=...)``,
since it carries a client secret and ``config.json`` is a file people commit.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .config import AuthConfig
from .types import Principal

logger = logging.getLogger(__name__)


class PrincipalError(ValueError):
    """A verified token that cannot stand for a principal: no ``sub`` or no
    ``iss``. Verified but unusable is a misconfiguration at the issuer, and
    the call is refused rather than treated as anonymous."""


@dataclass(frozen=True)
class PrincipalMapping:
    """How a token's claims become a :class:`Principal`."""

    roles_claim: str = "roles"
    role_map: Mapping[str, str] | None = None


_unmapped_seen: set[tuple[str, str]] = set()


def _navigate(claims: Mapping[str, Any], dotted: str) -> Any:
    node: Any = claims
    for part in dotted.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return None
        node = node[part]
    return node


def _roles(claims: Mapping[str, Any], mapping: PrincipalMapping, iss: str) -> frozenset[str]:
    raw = _navigate(claims, mapping.roles_claim)
    if raw is None:
        # The demo's own tokens carry one role as a string under ``role``;
        # read it when the configured claim is absent, as a one-element list.
        single = claims.get("role") if mapping.roles_claim == "roles" else None
        raw = [single] if isinstance(single, str) else []
    elif isinstance(raw, str):
        raw = [raw]
    elif not isinstance(raw, list):
        raw = []
    values = [v for v in raw if isinstance(v, str) and v]
    if mapping.role_map is None:
        return frozenset(values)
    out: set[str] = set()
    for v in values:
        if v in mapping.role_map:
            out.add(mapping.role_map[v])
        elif (iss, v) not in _unmapped_seen:
            _unmapped_seen.add((iss, v))
            logger.warning(
                "Role %r from issuer %r is not in the configured role_map; "
                "dropped (logged once per issuer and value)", v, iss,
            )
    return frozenset(out)


def principal_from_claims(
    claims: Mapping[str, Any],
    mapping: PrincipalMapping | None = None,
    *,
    client_id: str | None = None,
) -> Principal:
    """Build the principal a verified token's ``claims`` assert.

    ``client_id`` is the agent the token was issued to, as the verifier
    reports it; absent that, the ``client_id`` or ``azp`` claim. Raises
    :class:`PrincipalError` on a token with no usable ``sub`` or ``iss``.
    """
    mapping = mapping or PrincipalMapping()
    sub, iss = claims.get("sub"), claims.get("iss")
    if not isinstance(sub, str) or not sub:
        raise PrincipalError("the verified token carries no 'sub', so it names nobody")
    if not isinstance(iss, str) or not iss:
        raise PrincipalError("the verified token carries no 'iss', so nobody vouches for it")
    if client_id is None:
        for key in ("client_id", "azp"):
            if isinstance(claims.get(key), str) and claims[key]:
                client_id = claims[key]
                break
    auth_time = claims.get("auth_time")
    amr = claims.get("amr")
    acr = claims.get("acr")
    return Principal(
        sub=sub,
        iss=iss,
        roles=_roles(claims, mapping, iss),
        client_id=client_id,
        auth_time=int(auth_time) if isinstance(auth_time, (int, float)) and not isinstance(auth_time, bool) else None,
        amr=tuple(v for v in amr if isinstance(v, str)) if isinstance(amr, list) else None,
        acr=acr if isinstance(acr, str) and acr else None,
    )


# Same bound as DiscoveredToolsFilter, and for the same reason it is an LRU
# rather than a refusal: the thing a binding protects is the session's
# discovery set, which is evicted on the same bound, so an evicted binding
# guards nothing that still exists.
MAX_BOUND_SESSIONS = 4096


class SessionPrincipals:
    """Each MCP session acts for one principal, fixed on its first
    authenticated request.

    FastMCP verifies the bearer per request, so without this a session could
    change hands mid-conversation: the discovery set scoped to it, and
    anything else a filter keyed on the session, would belong to someone
    else. A later request on a bound session carrying a different ``sub``
    is refused; the same ``sub`` with a refreshed token is the normal case
    and passes. Keyed on ``sub`` and ``iss`` together, since two issuers may
    both have a ``user-1``.
    """

    def __init__(self, max_sessions: int = MAX_BOUND_SESSIONS) -> None:
        self._by_session: dict[str, tuple[str, str]] = {}
        self._max_sessions = max_sessions

    def bind(self, session_id: str | None, principal: Principal | None) -> None:
        """Bind, or check against the existing binding. Raises
        :class:`PrincipalError` on a mismatch. No session (stdio) or no
        principal (no inbound auth) binds nothing."""
        if session_id is None or principal is None:
            return
        who = (principal.iss, principal.sub)
        bound = self._by_session.pop(session_id, None)
        if bound is not None and bound != who:
            self._by_session[session_id] = bound  # the original binding stands
            raise PrincipalError(
                "this session is bound to a different principal; a session acts "
                "for the principal that opened it. Open a new session for the "
                "new principal."
            )
        self._by_session[session_id] = who  # re-inserted => most recent
        while len(self._by_session) > self._max_sessions:
            self._by_session.pop(next(iter(self._by_session)))

    def bound_to(self, session_id: str) -> tuple[str, str] | None:
        return self._by_session.get(session_id)


def principal_from_token(token: Any, mapping: PrincipalMapping | None = None) -> Principal | None:
    """The principal behind FastMCP's ``AccessToken``, or ``None`` when there
    is no token (stdio, or an HTTP deployment with no ``auth``)."""
    if token is None:
        return None
    claims = getattr(token, "claims", None) or {}
    return principal_from_claims(claims, mapping, client_id=getattr(token, "client_id", None))


def build_auth_provider(auth: AuthConfig) -> Any:
    """The ``JWTVerifier`` an ``auth`` config block describes."""
    from fastmcp.server.auth.providers.jwt import JWTVerifier

    public_key = auth.public_key_file.read_text() if auth.public_key_file is not None else None
    return JWTVerifier(
        issuer=auth.issuer,
        audience=auth.audience,
        jwks_uri=auth.jwks_uri,
        public_key=public_key,
        algorithm=auth.algorithm,
    )

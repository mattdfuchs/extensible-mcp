# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Verifiable-credential CallFilter for extensible-mcp.

For each gated tool call, the filter pulls two bundles from the arguments —
``vc_request`` and ``vc_authorization`` — and verifies the full chain:

1. Request VC signature against the originator's did:key.
2. Authorization VC signature against the approver's did:key.
3. Binding: authorization carries the request's ``jti`` and the SHA-256 hash
   of the request's compact JWS string.
4. Temporal validity (``nbf <= now < exp``) on both VCs.
5. Both signers carry a current FamilyMembership VC signed by a trusted
   ``did:web`` admin; each membership's ``sub`` equals the corresponding
   signer's did:key.
6. The admin's ``did:web`` resolves to a document whose Ed25519 public key
   matches the membership signature.

On success, both VC bundles are stripped from ``arguments`` before forwarding
to the downstream tool.
"""

from __future__ import annotations

import base64
import fnmatch
import json
import logging
import time
from typing import Any, Callable

from extensible_mcp import CallFilterResult, CallRequest
from household_identity.common import did as did_mod
from household_identity.common import jws, vc

from .config import VCConfig
from .did_resolver import DidWebResolver

logger = logging.getLogger("extensible_mcp_vc.filter")


class VCVerificationError(Exception):
    pass


class VCCallFilter:
    def __init__(
        self,
        vc_config: VCConfig,
        *,
        resolver: DidWebResolver | None = None,
        clock: Callable[[], int] = lambda: int(time.time()),
    ) -> None:
        self.config = vc_config
        self.resolver = resolver or DidWebResolver(
            cache_ttl_seconds=vc_config.did_web_cache_ttl_seconds
        )
        for did, doc in vc_config.preresolved_did_documents.items():
            self.resolver.preload(did, doc)
        self._gated_patterns: list[str] = list(vc_config.gated_tools)
        self._optional_auth_patterns: list[str] = list(
            vc_config.optional_authorization_tools
        )
        self._clock = clock
        logger.info(
            "[VC] filter initialized: gated=%s, optional_auth=%s, "
            "trusted_admin_dids=%s, preloaded DIDs in resolver cache: %s "
            "(resolver id=%s)",
            self._gated_patterns,
            self._optional_auth_patterns,
            list(vc_config.trusted_admin_dids),
            list(self.resolver._cache.keys()),
            id(self.resolver),
        )

    def is_gated(self, tool_name: str) -> bool:
        return any(fnmatch.fnmatch(tool_name, p) for p in self._gated_patterns)

    def is_optional_auth(self, tool_name: str) -> bool:
        return any(
            fnmatch.fnmatch(tool_name, p) for p in self._optional_auth_patterns
        )

    async def check(self, request: CallRequest) -> CallFilterResult:
        gated = self.is_gated(request.tool_name)
        optional_auth = self.is_optional_auth(request.tool_name) and not gated
        if not gated and not optional_auth:
            return CallFilterResult(
                allowed=True,
                tool_name=request.tool_name,
                arguments=request.arguments,
            )

        args = dict(request.arguments)
        raw_req = args.pop("vc_request", None)
        raw_auth = args.pop("vc_authorization", None)
        bundle_req = _coerce_bundle(raw_req)
        bundle_auth = _coerce_bundle(raw_auth)

        mode = "gated" if gated else "optional-auth"
        logger.info(
            "[VC] %s call to %r — payload (minus VCs): %s",
            mode,
            request.tool_name,
            json.dumps(args, default=str),
        )
        logger.info(
            "[VC] vc_request: raw_type=%s, coerced=%s%s; "
            "vc_authorization: raw_type=%s, coerced=%s%s",
            type(raw_req).__name__,
            bundle_req is not None,
            _bundle_diag(raw_req, bundle_req),
            type(raw_auth).__name__,
            bundle_auth is not None,
            _bundle_diag(raw_auth, bundle_auth),
        )

        if bundle_req is None:
            logger.warning(
                "[VC] ✗ denied %r: missing or malformed vc_request bundle",
                request.tool_name,
            )
            return _deny(request, "missing or malformed vc_request bundle")
        if gated and bundle_auth is None:
            logger.warning(
                "[VC] ✗ denied %r: missing or malformed vc_authorization bundle",
                request.tool_name,
            )
            return _deny(request, "missing or malformed vc_authorization bundle")

        try:
            await self._verify(bundle_req, bundle_auth)
        except VCVerificationError as e:
            logger.warning("[VC] ✗ denied %r: %s", request.tool_name, e)
            return _deny(request, str(e))

        # Always leave a marker so downstream policy filters (e.g.
        # PriceTierFilter) can read which VCs were verified, without
        # caring whether the VC config gated this tool fully or only
        # required the request VC. In fully-gated mode, both flags are
        # True by construction (we wouldn't have reached this point with
        # either missing). In optional-auth mode, the authorization flag
        # reflects what the LLM actually supplied.
        args["_verified_vcs"] = {
            "request": True,
            "authorization": bundle_auth is not None,
        }
        logger.info(
            "[VC] ✓ verified — forwarding %r to downstream pipeline "
            "(verified: request=True, authorization=%s)",
            request.tool_name,
            bundle_auth is not None,
        )
        return CallFilterResult(
            allowed=True, tool_name=request.tool_name, arguments=args
        )

    async def _verify(
        self,
        bundle_req: dict[str, Any],
        bundle_auth: dict[str, Any] | None,
    ) -> None:
        now = self._clock()

        req_claims = _verify_did_key_signed_vc(
            bundle_req["token"], label="request VC"
        )
        logger.info(
            "[VC] ✓ request VC signature (iss=%s, jti=%s)",
            req_claims.get("iss"),
            req_claims.get("jti"),
        )
        _check_temporal(req_claims, now, label="request VC")
        logger.info(
            "[VC] ✓ request VC within validity window (exp=%s)",
            req_claims.get("exp"),
        )

        if bundle_auth is not None:
            auth_claims = _verify_did_key_signed_vc(
                bundle_auth["token"], label="authorization VC"
            )
            logger.info(
                "[VC] ✓ authorization VC signature (iss=%s)",
                auth_claims.get("iss"),
            )
            _check_temporal(auth_claims, now, label="authorization VC")
            logger.info(
                "[VC] ✓ authorization VC within validity window (exp=%s)",
                auth_claims.get("exp"),
            )

            auth_cs = auth_claims.get("vc", {}).get("credentialSubject", {})
            if auth_cs.get("authorizes_request") != req_claims.get("jti"):
                raise VCVerificationError(
                    "authorization VC does not bind to the request jti"
                )
            logger.info(
                "[VC] ✓ binding: auth.authorizes_request == req.jti (%s)",
                req_claims.get("jti"),
            )
            if auth_cs.get("request_hash") != vc.hash_request(bundle_req["token"]):
                raise VCVerificationError(
                    "authorization VC does not bind to the request content hash"
                )
            logger.info(
                "[VC] ✓ binding: auth.request_hash == sha256(req.token)"
            )

            await self._verify_membership(
                bundle_auth.get("membership"),
                expected_subject=auth_claims["iss"],
                now=now,
                who="approver",
            )

        await self._verify_membership(
            bundle_req.get("membership"),
            expected_subject=req_claims["iss"],
            now=now,
            who="originator",
        )

    async def _verify_membership(
        self,
        membership_token: Any,
        *,
        expected_subject: str,
        now: int,
        who: str = "signer",
    ) -> None:
        if not isinstance(membership_token, str) or not membership_token:
            raise VCVerificationError(
                f"missing membership VC for {expected_subject}"
            )
        claims = _peek_jwt(membership_token)
        admin_did = claims.get("iss")
        if admin_did not in self.config.trusted_admin_dids:
            raise VCVerificationError(
                f"membership issued by untrusted admin {admin_did!r}"
            )
        logger.info(
            "[VC] looking up admin key for %r — cached DIDs at this moment: "
            "%s (resolver id=%s)",
            admin_did,
            list(self.resolver._cache.keys()),
            id(self.resolver),
        )
        try:
            admin_key = await self.resolver.public_key(admin_did)
        except Exception as e:
            raise VCVerificationError(
                f"could not resolve admin {admin_did}: {e}"
            )
        try:
            jws.verify_jwt(membership_token, key=admin_key)
        except Exception as e:
            raise VCVerificationError(f"membership signature invalid: {e}")
        _check_temporal(claims, now, label="membership VC")
        if claims.get("sub") != expected_subject:
            raise VCVerificationError(
                f"membership subject {claims.get('sub')!r} does not match "
                f"signer {expected_subject!r}"
            )
        logger.info(
            "[VC] ✓ %s (%s) membership verified — signed by admin %s, "
            "role=%s, exp=%s",
            who,
            expected_subject,
            admin_did,
            claims.get("vc", {}).get("credentialSubject", {}).get("role"),
            claims.get("exp"),
        )


def _coerce_bundle(value: Any) -> dict[str, Any] | None:
    """Return the bundle as a dict, or None if it isn't a valid bundle shape.

    Tolerates a JSON-encoded string: some LLM/MCP-client combinations stringify
    object-typed tool results on the way back through the next tool call, even
    though the consumer's input schema declares `vc_request` / `vc_authorization`
    as objects. Parsing here is cheap and avoids a round-trip the LLM keeps
    failing.
    """
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return None
    if isinstance(value, dict) and isinstance(value.get("token"), str):
        return value
    return None


def _bundle_diag(raw: Any, coerced: Any) -> str:
    """Short diagnostic suffix for the call-time log.

    Empty string when everything looks fine; otherwise a brief explanation
    of what landed in the slot and why ``_coerce_bundle`` rejected it. Keeps
    the log line useful without dumping full JWS tokens.
    """
    if raw is None:
        return " (absent)"
    if coerced is not None:
        return ""
    if isinstance(raw, str):
        return f" (string of length {len(raw)}; couldn't json.loads or no `token` field)"
    if isinstance(raw, dict):
        keys = sorted(raw.keys())
        return f" (dict with keys {keys}; no string `token` field)"
    return f" (unexpected type {type(raw).__name__}: {str(raw)[:80]!r})"


def _deny(request: CallRequest, reason: str) -> CallFilterResult:
    return CallFilterResult(
        allowed=False,
        reason=f"VC verification failed: {reason}",
        tool_name=request.tool_name,
        arguments=request.arguments,
    )


def _peek_jwt(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise VCVerificationError("not a compact JWS")
    pad = "=" * (-len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(parts[1] + pad))
    except Exception as e:
        raise VCVerificationError(f"invalid JWT payload: {e}")


def _verify_did_key_signed_vc(token: str, *, label: str) -> dict[str, Any]:
    claims = _peek_jwt(token)
    issuer = claims.get("iss")
    if not isinstance(issuer, str) or not issuer.startswith("did:key:"):
        raise VCVerificationError(
            f"{label} issuer must be a did:key, got {issuer!r}"
        )
    try:
        pubkey = did_mod.did_key_to_public_key(issuer)
    except ValueError as e:
        raise VCVerificationError(f"{label} issuer DID is malformed: {e}")
    try:
        jws.verify_jwt(token, key=pubkey)
    except Exception as e:
        raise VCVerificationError(f"{label} signature invalid: {e}")
    return claims


def _check_temporal(claims: dict[str, Any], now: int, *, label: str) -> None:
    nbf = claims.get("nbf", 0)
    exp = claims.get("exp", 0)
    if not isinstance(nbf, int) or not isinstance(exp, int):
        raise VCVerificationError(f"{label} has non-integer nbf/exp")
    if not (nbf <= now < exp):
        raise VCVerificationError(
            f"{label} outside its validity window "
            f"(nbf={nbf}, exp={exp}, now={now})"
        )

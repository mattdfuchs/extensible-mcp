# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Verifiable Credential envelope constructors for the family-network use case.

Two credential types so far:

- ``ActionRequest`` — signed by an originator (e.g., a kid) describing an
  action they want performed. Carries enough detail for an approver to make
  an informed decision.
- ``ActionAuthorization`` — signed by an approver (e.g., a parent) bound to
  a specific ActionRequest via the request's ``jti`` and a SHA-256 hash of
  its serialized form. The binding prevents the LLM from re-pairing an
  approver's authorization with a different request.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

VC_CONTEXT = ["https://www.w3.org/2018/credentials/v1"]


def _now() -> int:
    return int(time.time())


def _new_jti() -> str:
    return f"urn:uuid:{uuid.uuid4()}"


def make_action_request(
    *,
    issuer_did: str,
    request_type: str,
    details: dict[str, Any],
    ttl_seconds: int = 600,
    jti: str | None = None,
) -> dict[str, Any]:
    """Build a JWT-VC payload for an ActionRequest credential.

    The result is unsigned; pass it to ``jws.sign_jwt`` with the originator's
    private key. ``details`` is a free-form dict whose schema is
    application-specific (e.g., {"action": "spend", "amount": 15.00, ...}).
    """
    now = _now()
    return {
        "iss": issuer_did,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": jti or _new_jti(),
        "vc": {
            "@context": list(VC_CONTEXT),
            "type": ["VerifiableCredential", "ActionRequest"],
            "credentialSubject": {
                "id": issuer_did,
                "requests": {"type": request_type, **details},
            },
        },
    }


def hash_request(signed_request_jwt: str) -> str:
    """Compute the SHA-256 binding hash of a signed request JWT.

    The binding hash is over the *compact JWS string itself* (the three
    dot-separated segments), which is what an approver actually sees and
    what the proxy actually receives. Hashing the wire form rather than a
    re-serialized payload avoids canonicalization ambiguity.
    """
    digest = hashlib.sha256(signed_request_jwt.encode("ascii")).hexdigest()
    return f"sha256:{digest}"


def make_action_authorization(
    *,
    issuer_did: str,
    request_jti: str,
    request_hash: str,
    scope: dict[str, Any],
    ttl_seconds: int = 14400,  # 4 hours by default
    jti: str | None = None,
) -> dict[str, Any]:
    """Build a JWT-VC payload for an ActionAuthorization credential.

    The result is unsigned; pass it to ``jws.sign_jwt`` with the approver's
    private key. The authorization is bound to a specific request via
    ``request_jti`` and ``request_hash`` (use ``hash_request`` to compute
    the latter over the originator's signed request JWT).
    """
    now = _now()
    return {
        "iss": issuer_did,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": jti or _new_jti(),
        "vc": {
            "@context": list(VC_CONTEXT),
            "type": ["VerifiableCredential", "ActionAuthorization"],
            "credentialSubject": {
                "id": issuer_did,
                "authorizes_request": request_jti,
                "request_hash": request_hash,
                "scope": dict(scope),
            },
        },
    }


def _canonical_json(payload: dict[str, Any]) -> bytes:
    """Deterministic JSON serialization (sorted keys, compact separators).

    Used when hashing a VC payload independent of any signed JWS string.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

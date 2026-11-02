# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""FamilyMembership VC: admin (did:web) attests a member's did:key and role.

The membership VC is the bridge between the two halves of the trust framework.
A member's per-action request and authorization VCs are signed by their
did:key; the verifier trusts those keys only because a current membership VC,
signed by the family admin's did:web, asserts the binding.

It can carry a second binding, signed by the same admin: the member's
**accounts** at identity providers, each ``{"idp", "account"}`` -- the
issuer of a session token and the member's subject at that issuer. Named so
because a session token's ``iss``/``sub`` and a request credential's
``iss`` (the member's ``did:key``) are different things, and a credential
that used ``iss`` for both would invite the confusion. With it, a proxy that
knows who a session acts for (the token) and whose key signed a request (the
credential) can check they are the same person on the admin's word, rather
than trusting the identity provider's namespace to line up with the
family's. A list, because one member may hold accounts at two providers.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterable
from typing import Any

from ..common.vc import VC_CONTEXT

MEMBERSHIP_TYPE = ["VerifiableCredential", "FamilyMembership"]


def make_membership_vc(
    *,
    admin_did: str,
    member_did: str,
    role: str,
    ttl_seconds: int = 365 * 24 * 3600,
    jti: str | None = None,
    accounts: Iterable[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Build a JWT-VC payload binding ``member_did`` to the family under ``role``.

    ``accounts`` are ``(idp, account)`` pairs: the member's accounts at
    identity providers, bound by the same admin signature. Omitted, the
    credential carries no ``accounts`` field at all, so every credential
    issued before the field existed is unchanged.

    Unsigned; pass to ``jws.sign_jwt`` with the admin's private key.
    """
    subject: dict[str, Any] = {
        "id": member_did,
        "role": role,
        "family": admin_did,
    }
    if accounts is not None:
        bound = []
        for idp, account in accounts:
            if not isinstance(idp, str) or not idp or not isinstance(account, str) or not account:
                raise ValueError("each account is a (idp, account) pair of non-empty strings")
            bound.append({"idp": idp, "account": account})
        if bound:
            subject["accounts"] = bound
    now = int(time.time())
    return {
        "iss": admin_did,
        "sub": member_did,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": jti or f"urn:uuid:{uuid.uuid4()}",
        "vc": {
            "@context": list(VC_CONTEXT),
            "type": list(MEMBERSHIP_TYPE),
            "credentialSubject": subject,
        },
    }

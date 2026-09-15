# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""FamilyMembership VC: admin (did:web) attests a member's did:key and role.

The membership VC is the bridge between the two halves of the trust framework.
A member's per-action request and authorization VCs are signed by their
did:key; the verifier trusts those keys only because a current membership VC,
signed by the family admin's did:web, asserts the binding.
"""

from __future__ import annotations

import time
import uuid
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
) -> dict[str, Any]:
    """Build a JWT-VC payload binding ``member_did`` to the family under ``role``.

    Unsigned; pass to ``jws.sign_jwt`` with the admin's private key.
    """
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
            "credentialSubject": {
                "id": member_did,
                "role": role,
                "family": admin_did,
            },
        },
    }

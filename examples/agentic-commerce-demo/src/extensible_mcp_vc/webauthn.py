# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Verify a WebAuthn (FIDO2) assertion and bind it to a specific action.

The approval primitive for the phone-based approver (NOTES.md Layer 3, "Build
Direction: WebAuthn Approval + Stripe Rail"). A platform authenticator (Secure
Enclave / Android Keystore), gated by biometric, signs over a challenge that we
set to ``hash(action)``. This module verifies that signature (ES256 / P-256)
and — the load-bearing property — that the signed challenge equals the hash of
the *exact* action being authorized, so a signature obtained for one action
cannot authorize a different one. A manipulated agent can carry the evidence
but can neither forge it nor redirect it.

What is verified here is real and complete for the demo; what is deferred to a
native-app release is WYSIWYS (that the human *saw* the true action in a
trusted surface, not just that the signature binds it) — a narrower,
compromised-approval-page threat, distinct from the untrusted-agent threat this
fully addresses.

Spike scope: assertion verification + action binding, testable without a
browser. Enrollment (extracting the public key from the COSE key that
``navigator.credentials.create()`` returns) is a small addition; this verifier
takes the enrolled P-256 public key directly, with a helper to build it from
the ``(x, y)`` coordinates a COSE EC2 key carries. When wired into the policy
bundle this becomes a proxy host builtin alongside ``io.jwt.verify_eddsa``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# authenticatorData flag bits (WebAuthn §6.1).
_FLAG_UP = 0x01  # user present
_FLAG_UV = 0x04  # user verified (biometric / PIN)


class WebAuthnError(Exception):
    """An assertion failed verification or did not bind the intended action."""


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def extract_challenge(client_data_json: bytes) -> bytes:
    """The challenge bytes the authenticator signed, decoded from clientDataJSON."""
    return b64url_decode(json.loads(client_data_json).get("challenge", ""))


def ec_public_key_from_xy(x: bytes, y: bytes) -> ec.EllipticCurvePublicKey:
    """Build a P-256 public key from the ``(x, y)`` a COSE EC2 key carries
    (COSE labels -2 and -3). This is the bridge from the enrolled credential to
    a key this verifier can use."""
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
    )
    return numbers.public_key()


def jwk_string_to_public_key(jwk: str) -> ec.EllipticCurvePublicKey:
    """Parse a P-256 EC public JWK (a JSON *string*) into a public key.

    The builtin key seam (the JWK-string convention of seam 2).
    Expects ``kty=EC``, ``crv=P-256``, and base64url ``x``/``y`` — the shape the
    admin-attested enrollment VC carries for the passkey."""
    data = json.loads(jwk)
    if data.get("kty") != "EC" or data.get("crv") != "P-256":
        raise WebAuthnError("JWK is not an EC P-256 key")
    try:
        return ec_public_key_from_xy(b64url_decode(data["x"]), b64url_decode(data["y"]))
    except KeyError as e:
        raise WebAuthnError("JWK missing x/y") from e


# --------------------------------------------------------------------------- #
# Enrollment: recover the public key the browser registered
# --------------------------------------------------------------------------- #
#
# ``navigator.credentials.create()`` returns an *attestationObject* (CBOR)
# whose ``authData`` embeds the new credential's public key as a COSE key
# (also CBOR). We need just enough CBOR to read those two structures. A
# dependency-free minimal decoder covers the subset they use: unsigned and
# negative integers, byte and text strings, arrays, and maps.


def _cbor_decode(data: bytes, off: int = 0) -> tuple[Any, int]:
    """Decode one CBOR item at ``off``; return ``(value, next_offset)``."""
    ib = data[off]
    off += 1
    major, ai = ib >> 5, ib & 0x1F

    def _len(ai: int, off: int) -> tuple[int, int]:
        if ai < 24:
            return ai, off
        if ai == 24:
            return data[off], off + 1
        if ai == 25:
            return int.from_bytes(data[off : off + 2], "big"), off + 2
        if ai == 26:
            return int.from_bytes(data[off : off + 4], "big"), off + 4
        if ai == 27:
            return int.from_bytes(data[off : off + 8], "big"), off + 8
        raise WebAuthnError("unsupported CBOR length encoding")

    if major == 0:  # unsigned int
        return _len(ai, off)
    if major == 1:  # negative int
        val, off = _len(ai, off)
        return -1 - val, off
    if major == 2:  # byte string
        n, off = _len(ai, off)
        return data[off : off + n], off + n
    if major == 3:  # text string
        n, off = _len(ai, off)
        return data[off : off + n].decode(), off + n
    if major == 4:  # array
        n, off = _len(ai, off)
        arr = []
        for _ in range(n):
            item, off = _cbor_decode(data, off)
            arr.append(item)
        return arr, off
    if major == 5:  # map
        n, off = _len(ai, off)
        out: dict[Any, Any] = {}
        for _ in range(n):
            k, off = _cbor_decode(data, off)
            v, off = _cbor_decode(data, off)
            out[k] = v
        return out, off
    raise WebAuthnError(f"unsupported CBOR major type {major}")


def cose_ec2_to_public_key(cose_key: bytes) -> ec.EllipticCurvePublicKey:
    """A COSE EC2 P-256 key (as CBOR) → an EC public key.

    COSE labels: 1=kty (2=EC2), 3=alg (-7=ES256), -1=crv (1=P-256),
    -2=x, -3=y.
    """
    key, _ = _cbor_decode(cose_key)
    if not isinstance(key, dict):
        raise WebAuthnError("COSE key is not a map")
    if key.get(1) != 2:
        raise WebAuthnError("COSE key is not EC2 (kty != 2)")
    if key.get(3) != -7:
        raise WebAuthnError("COSE key is not ES256 (alg != -7)")
    if key.get(-1) != 1:
        raise WebAuthnError("COSE key is not P-256 (crv != 1)")
    x, y = key.get(-2), key.get(-3)
    if not (isinstance(x, bytes) and isinstance(y, bytes)):
        raise WebAuthnError("COSE key missing x/y coordinates")
    return ec_public_key_from_xy(x, y)


def parse_authenticator_data(
    authenticator_data: bytes,
) -> tuple[bytes, ec.EllipticCurvePublicKey]:
    """From registration ``authData``, return ``(credential_id, public_key)``.

    Layout: rpIdHash(32) + flags(1) + signCount(4) + attestedCredentialData,
    where attestedCredentialData = aaguid(16) + credIdLen(2) + credId +
    COSE public key. Any trailing extensions are ignored (the COSE decoder
    stops at the key's end)."""
    if len(authenticator_data) < 37:
        raise WebAuthnError("authenticatorData too short")
    if not authenticator_data[32] & 0x40:  # AT: attested credential data
        raise WebAuthnError("no attested credential data (AT flag unset)")
    off = 37 + 16  # past rpIdHash+flags+signCount, then skip aaguid
    cred_id_len = int.from_bytes(authenticator_data[off : off + 2], "big")
    off += 2
    cred_id = authenticator_data[off : off + cred_id_len]
    off += cred_id_len
    return cred_id, cose_ec2_to_public_key(authenticator_data[off:])


def parse_registration(
    attestation_object: bytes,
) -> tuple[bytes, ec.EllipticCurvePublicKey]:
    """From a ``navigator.credentials.create()`` attestationObject, return
    ``(credential_id, public_key)``.

    The attestation *statement* is not verified — enrollment is trusted here as
    a first-party channel (``none``/self attestation), which is standard when
    the relying party controls the enrollment surface. Verifying attestation
    (proving the authenticator model) is a separate, optional hardening step.
    """
    obj, _ = _cbor_decode(attestation_object)
    if not isinstance(obj, dict) or not isinstance(obj.get("authData"), bytes):
        raise WebAuthnError("attestationObject has no authData")
    return parse_authenticator_data(obj["authData"])


def verify_webauthn_signature(
    *,
    public_key: ec.EllipticCurvePublicKey,
    authenticator_data: bytes,
    client_data_json: bytes,
    signature: bytes,
    expected_origin: str,
    expected_rp_id: str,
    require_user_verified: bool = True,
) -> None:
    """Verify an ES256 WebAuthn assertion's signature, origin, rpId, and
    user-present / user-verified flags — but **not** the challenge.

    This is the host-builtin surface: the challenge→action
    *binding* is checked separately, in the policy, so the faithfulness theorem
    covers "the signature is over the exact action." Raises
    :class:`WebAuthnError` on any failure.
    """
    try:
        client_data = json.loads(client_data_json)
    except ValueError as e:
        raise WebAuthnError(f"clientDataJSON is not valid JSON: {e}") from e
    if client_data.get("type") != "webauthn.get":
        raise WebAuthnError(f"unexpected ceremony type {client_data.get('type')!r}")
    if client_data.get("origin") != expected_origin:
        raise WebAuthnError(f"origin mismatch: {client_data.get('origin')!r}")

    if len(authenticator_data) < 37:
        raise WebAuthnError("authenticatorData too short")
    if authenticator_data[:32] != hashlib.sha256(expected_rp_id.encode()).digest():
        raise WebAuthnError("rpId hash mismatch")
    flags = authenticator_data[32]
    if not flags & _FLAG_UP:
        raise WebAuthnError("user-present flag not set")
    if require_user_verified and not flags & _FLAG_UV:
        raise WebAuthnError("user-verified (biometric) flag not set")

    signed = authenticator_data + hashlib.sha256(client_data_json).digest()
    try:
        public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise WebAuthnError("signature does not verify") from e


def verify_webauthn_assertion(
    *,
    public_key: ec.EllipticCurvePublicKey,
    authenticator_data: bytes,
    client_data_json: bytes,
    signature: bytes,
    expected_challenge: bytes,
    expected_origin: str,
    expected_rp_id: str,
    require_user_verified: bool = True,
) -> None:
    """Signature verification (:func:`verify_webauthn_signature`) *plus* the
    challenge→action binding: the signed challenge must equal
    ``expected_challenge``, supplied by the caller.

    Convenience for the standalone approval service, which owns both checks. In
    the policy-bundle-integrated path the builtin does the signature half and
    the policy does the binding half; the redundancy is harmless, the
    *absence* of the in-policy binding would not be.
    """
    verify_webauthn_signature(
        public_key=public_key,
        authenticator_data=authenticator_data,
        client_data_json=client_data_json,
        signature=signature,
        expected_origin=expected_origin,
        expected_rp_id=expected_rp_id,
        require_user_verified=require_user_verified,
    )
    if extract_challenge(client_data_json) != expected_challenge:
        raise WebAuthnError("assertion does not bind the intended action")

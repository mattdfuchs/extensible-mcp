# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""WebAuthn assertion verification + action binding (no browser needed).

Mints a real P-256 keypair, constructs a WebAuthn assertion the way a platform
authenticator would, and checks that the verifier accepts a valid, correctly
bound assertion and rejects every way it could go wrong — above all, that a
signature obtained for one action cannot authorize another. Also exercises the
challenge-excluded builtin surface and the JWK-string key seam."""

from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from extensible_mcp_vc.webauthn import (
    WebAuthnError,
    b64url_encode,
    ec_public_key_from_xy,
    jwk_string_to_public_key,
    spend_challenge,
    verify_webauthn_assertion,
    verify_webauthn_signature,
)

RP_ID = "approve.example"
ORIGIN = "https://approve.example"
ACTION = {"tool": "spend", "amountCents": 1500, "merchant": "acme"}
_UP_UV = 0x01 | 0x04


def _ch(action) -> bytes:
    return spend_challenge(action["tool"], action["amountCents"], action["merchant"])


def _mint(action, *, key=None, flags=_UP_UV, challenge_action=None, origin=ORIGIN,
          rp_id=RP_ID, ceremony="webauthn.get"):
    """Produce (public_key, authenticator_data, client_data_json, signature),
    signing over challenge = spend_challenge(action)."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    challenge = _ch(action if challenge_action is None else challenge_action)
    client_data = json.dumps(
        {"type": ceremony, "challenge": b64url_encode(challenge), "origin": origin}
    ).encode()
    auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + b"\x00\x00\x00\x01"
    signed = auth_data + hashlib.sha256(client_data).digest()
    return key.public_key(), auth_data, client_data, key.sign(signed, ec.ECDSA(hashes.SHA256()))


def _verify(pub, ad, cd, sig, *, action=ACTION, **kw):
    verify_webauthn_assertion(
        public_key=pub, authenticator_data=ad, client_data_json=cd, signature=sig,
        expected_challenge=_ch(action), expected_origin=ORIGIN, expected_rp_id=RP_ID, **kw,
    )


def test_valid_assertion_binds_the_action():
    _verify(*_mint(ACTION))  # no raise


def test_signature_for_one_action_cannot_authorize_another():
    # The load-bearing property. Sign approval for $15 to acme; a manipulated
    # agent then tries to spend it on $50,000 to an attacker.
    pub, ad, cd, sig = _mint(ACTION)
    attacker = {"tool": "spend", "amountCents": 5_000_000, "merchant": "attacker"}
    with pytest.raises(WebAuthnError, match="does not bind"):
        _verify(pub, ad, cd, sig, action=attacker)


def test_user_verification_required_by_default():
    pub, ad, cd, sig = _mint(ACTION, flags=0x01)  # present, not verified
    with pytest.raises(WebAuthnError, match="user-verified"):
        _verify(pub, ad, cd, sig)


def test_user_present_but_verification_optional_when_relaxed():
    _verify(*_mint(ACTION, flags=0x01), require_user_verified=False)  # no raise


def test_tampered_signature_rejected():
    pub, ad, cd, sig = _mint(ACTION)
    bad = bytearray(sig)
    bad[-1] ^= 0xFF
    with pytest.raises(WebAuthnError, match="signature"):
        _verify(pub, ad, cd, bytes(bad))


def test_wrong_key_rejected():
    pub, ad, cd, sig = _mint(ACTION)
    other = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(WebAuthnError, match="signature"):
        _verify(other, ad, cd, sig)


def test_origin_mismatch_rejected():
    with pytest.raises(WebAuthnError, match="origin"):
        _verify(*_mint(ACTION, origin="https://evil.example"))


def test_wrong_rp_rejected():
    with pytest.raises(WebAuthnError, match="rpId"):
        _verify(*_mint(ACTION, rp_id="evil.example"))


def test_registration_ceremony_type_rejected():
    with pytest.raises(WebAuthnError, match="ceremony type"):
        _verify(*_mint(ACTION, ceremony="webauthn.create"))


def test_public_key_from_xy_roundtrips():
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    rebuilt = ec_public_key_from_xy(nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big"))
    _, ad, cd, sig = _mint(ACTION, key=key)
    _verify(rebuilt, ad, cd, sig)


# -- the builtin surface: verify_webauthn_signature (challenge excluded) ------ #
def test_builtin_verifies_signature_without_the_challenge():
    # a valid assertion for one action verifies as a *signature* even when
    # asked about a different action — the builtin does not bind the action;
    # the policy (or the binding wrapper) does.
    pub, ad, cd, sig = _mint(ACTION)
    verify_webauthn_signature(
        public_key=pub, authenticator_data=ad, client_data_json=cd, signature=sig,
        expected_origin=ORIGIN, expected_rp_id=RP_ID,
    )  # no raise, no action supplied


def test_builtin_still_enforces_uv_and_signature():
    pub, ad, cd, sig = _mint(ACTION, flags=0x01)
    with pytest.raises(WebAuthnError, match="user-verified"):
        verify_webauthn_signature(
            public_key=pub, authenticator_data=ad, client_data_json=cd, signature=sig,
            expected_origin=ORIGIN, expected_rp_id=RP_ID,
        )


# -- the JWK-string key seam ------------------------------------------------- #
def test_jwk_string_key_verifies():
    key = ec.generate_private_key(ec.SECP256R1())
    n = key.public_key().public_numbers()
    jwk = json.dumps({
        "kty": "EC", "crv": "P-256",
        "x": b64url_encode(n.x.to_bytes(32, "big")),
        "y": b64url_encode(n.y.to_bytes(32, "big")),
    })
    _, ad, cd, sig = _mint(ACTION, key=key)
    _verify(jwk_string_to_public_key(jwk), ad, cd, sig)


def test_non_p256_jwk_rejected():
    with pytest.raises(WebAuthnError, match="P-256"):
        jwk_string_to_public_key(json.dumps({"kty": "OKP", "crv": "Ed25519", "x": "AA"}))

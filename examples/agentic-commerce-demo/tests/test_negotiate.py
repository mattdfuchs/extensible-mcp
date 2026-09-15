# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Stage 2 — the A2A negotiation, and its join to stage 1.

The family agent discovers a merchant, orders over A2A, and receives a
merchant-signed invoice. The properties under test:

- the merchant prices the order authoritatively from its own menu (the buyer
  agent cannot dictate the price);
- the returned invoice verifies against the merchant's published key;
- **the A2A channel is untrusted**: a manipulated buyer agent that alters the
  invoice after receiving it cannot get it approved — the signature breaks and
  the approval service refuses it before any human is involved;
- end to end: negotiate -> register trust -> request approval -> child + parent
  sign the invoice hash -> authorized. This is the whole stage-2-into-stage-1
  chain with no step trusted on an agent's word.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from extensible_mcp_vc.invoice import invoice_challenge, public_key_from_raw
from extensible_mcp_vc.negotiate import (
    NegotiationError,
    fetch_menu,
    fetch_merchant_card,
    negotiate_order,
)
from extensible_mcp_vc.webauthn import b64url_encode

from .webauthn_fixtures import assertion_for, attestation_object

ORDER = [{"name": "Large Pepperoni", "qty": 1}]  # 1800 cents -> child + parent


def _load(rel: str, name: str):
    path = Path(__file__).resolve().parents[1] / rel
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def merchant():
    mod = _load("examples/merchant_server.py", "merchant_server")
    return TestClient(mod.app)


@pytest.fixture
def approvals():
    mod = _load("examples/approval_service.py", "approval_service")
    return TestClient(mod.app)


def _enroll(client, role):
    key = ec.generate_private_key(ec.SECP256R1())
    cred_id = f"cred-{role}".encode()
    r = client.post("/register", json={
        "attestationObject": b64url_encode(attestation_object(key.public_key(), cred_id)),
        "role": role})
    assert r.status_code == 200
    return key, r.json()["credentialId"]


def _register_trust(approvals, merchant):
    """Buyer's one-time trust decision: read the merchant card, register its key."""
    card = fetch_merchant_card(merchant)
    r = approvals.post("/trust-merchant",
                       json={"merchantId": card["merchantId"], "publicKey": card["publicKey"]})
    assert r.status_code == 200
    return card


# -- the negotiation itself -------------------------------------------------- #
def test_menu_and_authoritative_pricing(merchant):
    menu = {i["name"]: i["priceCents"] for i in fetch_menu(merchant)}
    invoice, _ = negotiate_order(merchant, [{"name": "Large Pepperoni", "qty": 2}])
    assert invoice["totalCents"] == menu["Large Pepperoni"] * 2  # merchant, not buyer, sets price
    assert invoice["merchantId"] == "pizza-1"


def test_negotiated_invoice_verifies_against_the_merchant_card(merchant):
    card = fetch_merchant_card(merchant)
    trusted = {card["merchantId"]: public_key_from_raw(card["publicKey"])}
    # Verifying here (client-side, advisory) must not raise.
    invoice, sig = negotiate_order(merchant, ORDER, trusted_merchants=trusted)
    assert sig and invoice["items"] == ORDER


def test_unknown_menu_item_refused(merchant):
    with pytest.raises(NegotiationError):
        negotiate_order(merchant, [{"name": "Caviar", "qty": 1}])


def test_client_side_verify_catches_wrong_merchant_key(merchant):
    # The buyer holds a *different* key than the one the merchant actually signs
    # with, so its advisory client-side check rejects the response.
    bogus = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(NegotiationError, match="did not verify"):
        negotiate_order(merchant, ORDER, trusted_merchants={"pizza-1": bogus})


# -- the join to stage 1: negotiate -> approve ------------------------------- #
def test_end_to_end_negotiate_then_approve(merchant, approvals):
    _register_trust(approvals, merchant)
    ck, cid = _enroll(approvals, "child")
    pk, pid = _enroll(approvals, "parent")

    invoice, sig = negotiate_order(merchant, ORDER)
    req = approvals.post("/request-invoice", json={"invoice": invoice, "signature": sig}).json()
    assert set(req["required_roles"]) == {"child", "parent"}

    ch = invoice_challenge(invoice)
    approvals.post(f"/approve/{req['id']}", json={"credentialId": cid, **assertion_for(ck, ch)})
    out = approvals.post(f"/approve/{req['id']}",
                         json={"credentialId": pid, **assertion_for(pk, ch)}).json()
    # Fully approved; settlement is now a separate, explicit step (see /settle).
    assert out["status"] == "approved" and set(out["approved_roles"]) == {"child", "parent"}
    settled = approvals.post("/settle", json={"merchantId": invoice["merchantId"], "amountCents": invoice["totalCents"]}).json()
    assert settled["status"] == "settled"


def test_manipulated_buyer_agent_cannot_alter_terms(merchant, approvals):
    """The untrusted-channel property: a buyer agent that lowers the price after
    the merchant signs cannot get the altered invoice approved."""
    _register_trust(approvals, merchant)
    invoice, sig = negotiate_order(merchant, ORDER)
    invoice["totalCents"] = 1  # a manipulated relayer tries to cheapen the order
    r = approvals.post("/request-invoice", json={"invoice": invoice, "signature": sig})
    assert r.status_code == 400 and "signature" in r.json()["detail"]


def test_untrusted_merchant_rejected_even_after_negotiation(merchant, approvals):
    """A perfectly well-formed, correctly-signed invoice from a merchant the buyer
    never trusted is still refused (no /trust-merchant was called)."""
    invoice, sig = negotiate_order(merchant, ORDER)
    r = approvals.post("/request-invoice", json={"invoice": invoice, "signature": sig})
    assert r.status_code == 400 and "not in the trusted set" in r.json()["detail"]

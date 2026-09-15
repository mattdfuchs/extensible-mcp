# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The merchant desk: an untrusted clerk (LLM or scripted) proposes terms, the
merchant's policy decides what its signature can bind. The load-bearing case:
a manipulated clerk offering a 90% discount produces a *refusal*, not a signed
invoice."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from extensible_mcp_vc.invoice import public_key_from_raw, verify_invoice
from extensible_mcp_vc.merchant import (
    MerchantDesk,
    MerchantPolicy,
    list_price_negotiator,
    load_or_create_key,
)

MENU = {"margherita small": 1100, "pepperoni large": 1900, "white pie": 1600}


def _desk(negotiator=None) -> MerchantDesk:
    return MerchantDesk(
        merchant_id="tonys-pizza",
        merchant_name="Tony's Pizza",
        policy=MerchantPolicy(menu=MENU),
        key=Ed25519PrivateKey.generate(),
        negotiator=negotiator or list_price_negotiator,
    )


def test_list_price_invoice_signs_and_verifies():
    desk = _desk()
    out = desk.invoice([{"name": "pepperoni large", "qty": 2}])
    assert "invoice" in out
    inv = out["invoice"]
    assert inv["totalCents"] == 3800
    assert inv["items"][0]["priceCents"] == 1900  # filled at list
    trusted = {"tonys-pizza": public_key_from_raw(desk.card()["publicKey"])}
    verify_invoice(inv, out["signature"], trusted_merchants=trusted)  # no raise
    assert inv["nonce"] in desk.issued


def test_manipulated_clerk_cannot_sign_below_the_floor():
    # A 90% "discount" — whether from a sweet-talked LLM or a hostile buyer
    # agent — is refused by the policy, not signed.
    desk = _desk()
    out = desk.invoice([{"name": "pepperoni large", "qty": 1, "priceCents": 190}])
    assert "signature" not in out
    assert any("below the floor" in v for v in out["violations"])
    assert desk.issued == {}  # nothing was committed


def test_discount_within_the_envelope_signs():
    # 30% off list (the stated latitude) is exactly at the 0.7 floor.
    desk = _desk()
    out = desk.invoice([{"name": "white pie", "qty": 1, "priceCents": 1120}])
    assert "signature" in out


def test_off_menu_and_overpriced_and_quantity_are_refused():
    desk = _desk()
    assert any(
        "not on the menu" in v
        for v in desk.invoice([{"name": "sushi", "qty": 1}])["violations"]
    )
    assert any(
        "above list" in v
        for v in desk.invoice(
            [{"name": "white pie", "qty": 1, "priceCents": 2000}]
        )["violations"]
    )
    assert any(
        "bad quantity" in v
        for v in desk.invoice([{"name": "white pie", "qty": 99}])["violations"]
    )


def test_negotiator_failure_degrades_to_list_price():
    def broken(message, order, menu):
        raise RuntimeError("clerk fell over")

    desk = _desk(negotiator=broken)
    result = desk.negotiate("what do you have?")
    assert "menu" in result["reply"].lower() or "list price" in result["reply"].lower()


def test_merchant_key_persists(tmp_path):
    path = tmp_path / "merchant.key"
    first = load_or_create_key(path)
    second = load_or_create_key(path)
    assert (
        first.public_key().public_bytes_raw()
        == second.public_key().public_bytes_raw()
    )


# --------------------------------------------------------------------------- #
# Fulfillment: ship only against a rail-signed receipt; answer with a
# merchant-signed commitment — the closing artifact of the agreement chain.
# --------------------------------------------------------------------------- #

from extensible_mcp_vc.settlement import MockExecutor, settle  # noqa: E402


def _settled(desk):
    out = desk.invoice([{"name": "white pie", "qty": 1}], deliver_to="12 Main St")
    rail_key = Ed25519PrivateKey.generate()
    receipt, sig = settle(out["invoice"], executor=MockExecutor(), settlement_key=rail_key)
    return out["invoice"], receipt, sig, rail_key.public_key()


def test_fulfill_returns_signed_commitment_with_delivery():
    desk = _desk()
    invoice, receipt, sig, rail_pub = _settled(desk)
    result = desk.fulfill(receipt, sig, settlement_pub=rail_pub)
    c = result["commitment"]
    assert c["nonce"] == invoice["nonce"]
    assert c["deliverTo"] == "12 Main St"
    # the commitment verifies against the merchant card, like an invoice
    trusted = {"tonys-pizza": public_key_from_raw(desk.card()["publicKey"])}
    verify_invoice(c, result["signature"], trusted_merchants=trusted)


def test_replayed_receipt_cannot_reship():
    desk = _desk()
    _, receipt, sig, rail_pub = _settled(desk)
    assert "commitment" in desk.fulfill(receipt, sig, settlement_pub=rail_pub)
    assert "already fulfilled" in desk.fulfill(receipt, sig, settlement_pub=rail_pub)["error"]


def test_receipt_from_untrusted_rail_refused():
    desk = _desk()
    _, receipt, sig, _ = _settled(desk)
    stranger = Ed25519PrivateKey.generate().public_key()
    assert "rejected" in desk.fulfill(receipt, sig, settlement_pub=stranger)["error"]


def test_receipt_for_unissued_order_refused():
    desk = _desk()
    other = _desk()  # a different merchant's invoice
    _, receipt, sig, rail_pub = _settled(other)
    assert "no order issued here" in desk.fulfill(receipt, sig, settlement_pub=rail_pub)["error"]

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The merchant's agent desk: an LLM sales clerk whose *signing hand* is a
deterministic policy.

The symmetric half of the zero-trust story. The buyer's agent is untrusted
and caged by the family's policy; the merchant's agent is equally untrusted —
it can be sweet-talked, prompt-injected, or simply wrong — and is caged by the
*merchant's* policy. The LLM negotiates freely (tone, upsells, discounts); the
one thing it cannot do is bind the org: every invoice it proposes passes
through :class:`MerchantPolicy` before the merchant key signs, and an
out-of-bounds proposal is refused, not signed. Delegation of authority, org
configuration: the family delegates per-action to humans (wallet, passkey);
the merchant delegates a standing envelope to its clerk (price floor,
quantity bounds, quote TTL).

No API key configured → the desk degrades to a deterministic list-price
clerk, so containers and tests run without credentials.
"""

from __future__ import annotations

import json
import logging
import math
import os
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .invoice import sign_invoice
from .settlement import SettlementError, verify_receipt
from .webauthn import b64url_encode

logger = logging.getLogger("extensible_mcp_vc.merchant")

_DEFAULT_MODEL = "claude-sonnet-5"

# A negotiator maps (customer message, proposed order, menu) to
# {"reply": str, "order": [{name, qty, priceCents}] | None}. The order it
# returns is a *proposal* — the policy gate, not the negotiator, decides
# whether it can be signed.
Negotiator = Callable[[str, list[dict[str, Any]] | None, dict[str, int]], dict[str, Any]]


@dataclass
class MerchantPolicy:
    """The standing authority the org delegates to its clerk — deterministic
    bounds the LLM cannot argue its way past."""

    menu: dict[str, int]  # item name -> list price in cents
    floor_ratio: float = 0.7  # deepest allowed discount from list
    max_qty: int = 20
    max_total_cents: int = 50_000
    quote_ttl_seconds: int = 300

    def check_invoice(self, invoice: dict[str, Any], *, now: int | None = None) -> list[str]:
        """Violations that forbid signing; empty means the clerk may bind the org."""
        errors: list[str] = []
        items = invoice.get("items") or []
        if not items:
            errors.append("empty order")
        total = 0
        for item in items:
            name = item.get("name")
            if name not in self.menu:
                errors.append(f"not on the menu: {name!r}")
                continue
            qty = item.get("qty")
            if not isinstance(qty, int) or not (1 <= qty <= self.max_qty):
                errors.append(f"bad quantity for {name!r}: {qty!r} (1..{self.max_qty})")
                continue
            price = item.get("priceCents")
            floor = math.ceil(self.menu[name] * self.floor_ratio)
            if not isinstance(price, int) or price < floor:
                errors.append(
                    f"price for {name!r} below the floor: {price!r} < {floor} "
                    f"(list {self.menu[name]})"
                )
                continue
            if price > self.menu[name]:
                errors.append(
                    f"price for {name!r} above list: {price} > {self.menu[name]}"
                )
                continue
            total += price * qty
        if not errors and invoice.get("totalCents") != total:
            errors.append(
                f"totalCents {invoice.get('totalCents')!r} != sum of lines {total}"
            )
        if total > self.max_total_cents:
            errors.append(f"total {total} exceeds the desk limit {self.max_total_cents}")
        if invoice.get("currency") != "usd":
            errors.append(f"unsupported currency {invoice.get('currency')!r}")
        when = now if now is not None else int(time.time())
        exp = invoice.get("exp")
        if not isinstance(exp, int) or exp <= when or exp > when + self.quote_ttl_seconds + 60:
            errors.append(f"bad expiry {exp!r}")
        if not isinstance(invoice.get("nonce"), str) or not invoice["nonce"]:
            errors.append("missing nonce")
        return errors


def list_price_negotiator(
    message: str, order: list[dict[str, Any]] | None, menu: dict[str, int]
) -> dict[str, Any]:
    """The no-LLM clerk: everything at list price, no discounts, plain answers."""
    if order:
        priced = [
            {"name": i.get("name"), "qty": int(i.get("qty", 1)),
             "priceCents": menu.get(i.get("name"), 0)}
            for i in order
        ]
        return {"reply": "Happy to put that order together at list price.", "order": priced}
    listing = ", ".join(f"{n} (${p / 100:.2f})" for n, p in menu.items())
    return {"reply": f"Our menu: {listing}. Tell me what you'd like.", "order": None}


class AnthropicNegotiator:
    """The LLM clerk. One bounded call per turn — no agent loop, no tools; it
    only ever produces words and a proposed order. The prompt states the
    discount latitude, but nothing depends on it being obeyed: the policy
    gate re-checks every proposal."""

    def __init__(self, *, model: str | None = None, merchant_name: str = "the shop") -> None:
        self._model = model or os.environ.get("MERCHANT_MODEL", _DEFAULT_MODEL)
        self._merchant_name = merchant_name

    def __call__(
        self, message: str, order: list[dict[str, Any]] | None, menu: dict[str, int]
    ) -> dict[str, Any]:
        import anthropic

        system = (
            f"You are the sales clerk for {self._merchant_name}, a pizza shop. "
            f"Menu (name -> price in cents): {json.dumps(menu)}. "
            "You may offer discounts of up to 30% off list for large or repeat "
            "orders; never price below that, never invent menu items, never "
            "exceed 20 of anything. Respond ONLY with a JSON object "
            '{"reply": string, "order": [{"name": string, "qty": int, '
            '"priceCents": int}] | null}. "order" is your concrete proposal '
            "when the customer wants to buy; null when you are only answering."
        )
        user = json.dumps({"customer_message": message, "proposed_order": order})
        client = anthropic.Anthropic()
        response = client.messages.create(
            model=self._model,
            max_tokens=700,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(b.text for b in response.content if b.type == "text").strip()
        if text.startswith("```"):
            text = text.strip("`\n")
            text = text[text.index("{"):]
        parsed = json.loads(text)
        return {"reply": str(parsed.get("reply", "")), "order": parsed.get("order")}


def default_negotiator(merchant_name: str) -> Negotiator:
    """LLM clerk when a key is configured, list-price clerk otherwise."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        return AnthropicNegotiator(merchant_name=merchant_name)
    logger.info("no ANTHROPIC_API_KEY: merchant desk runs the list-price clerk")
    return list_price_negotiator


@dataclass
class MerchantDesk:
    """Negotiation + gated signing, bound to one merchant identity."""

    merchant_id: str
    merchant_name: str
    policy: MerchantPolicy
    key: Ed25519PrivateKey
    negotiator: Negotiator | None = None
    eta_minutes: int = 30
    issued: dict[str, dict[str, Any]] = field(default_factory=dict)
    fulfilled: set[str] = field(default_factory=set)

    def card(self) -> dict[str, Any]:
        return {
            "merchantId": self.merchant_id,
            "merchant": self.merchant_name,
            "publicKey": b64url_encode(self.key.public_key().public_bytes_raw()),
        }

    def negotiate(self, message: str, order: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        clerk = self.negotiator or default_negotiator(self.merchant_name)
        try:
            result = clerk(message, order, dict(self.policy.menu))
        except Exception as e:  # noqa: BLE001 - clerk trouble must not kill the desk
            logger.warning("negotiator failed (%s); answering at list price", e)
            result = list_price_negotiator(message, order, dict(self.policy.menu))
        return result

    def invoice(
        self, items: list[dict[str, Any]], *, deliver_to: str | None = None
    ) -> dict[str, Any]:
        """Sign an invoice for ``items`` — or refuse. Missing prices fill in at
        list; the policy gate has the final word regardless of who (human ask,
        LLM proposal, injected instruction) produced the numbers.

        ``deliver_to`` rides inside the signed terms: what the humans approve
        and what gets paid is also where it goes — the full-terms binding."""
        priced = []
        for item in items or []:
            qty = item.get("qty", 1)
            entry = {
                "name": item.get("name"),
                "qty": int(qty) if isinstance(qty, (int, float)) and not isinstance(qty, bool) else qty,
                "priceCents": item.get("priceCents", self.policy.menu.get(item.get("name"))),
            }
            priced.append(entry)
        total = sum(
            i["priceCents"] * i["qty"]
            for i in priced
            if isinstance(i.get("priceCents"), int) and isinstance(i.get("qty"), int)
        )
        invoice = {
            "merchantId": self.merchant_id,
            "merchant": self.merchant_name,
            "items": priced,
            "totalCents": total,
            "currency": "usd",
            "exp": int(time.time()) + self.policy.quote_ttl_seconds,
            "nonce": f"urn:uuid:{uuid.uuid4()}",
        }
        if deliver_to:
            invoice["deliverTo"] = str(deliver_to)
        violations = self.policy.check_invoice(invoice)
        if violations:
            logger.warning("refusing to sign invoice: %s", violations)
            return {
                "error": "the merchant's policy refuses to sign these terms",
                "violations": violations,
            }
        self.issued[invoice["nonce"]] = invoice
        return {"invoice": invoice, "signature": sign_invoice(invoice, self.key)}

    def fulfill(
        self,
        receipt: dict[str, Any],
        signature: str,
        *,
        settlement_pub: Ed25519PublicKey,
    ) -> dict[str, Any]:
        """Ship against a **signed payment receipt** — never on the buyer's
        word — and answer with a merchant-**signed fulfillment commitment**,
        the closing artifact of the agreement chain: after it, either party
        can prove the whole loop (terms → consent → payment → obligation).

        Single-use per invoice nonce: a replayed receipt cannot re-ship.
        """
        nonce = (receipt or {}).get("nonce")
        invoice = self.issued.get(nonce)
        if invoice is None:
            return {"error": f"no order issued here for nonce {nonce!r}"}
        if nonce in self.fulfilled:
            return {"error": "order already fulfilled"}
        try:
            verify_receipt(
                receipt, signature, settlement_key_pub=settlement_pub, invoice=invoice
            )
        except SettlementError as e:
            return {"error": f"receipt rejected: {e}"}
        self.fulfilled.add(nonce)
        commitment = {
            "kind": "fulfillment",
            "merchantId": self.merchant_id,
            "merchant": self.merchant_name,
            "nonce": nonce,
            "items": invoice["items"],
            "paymentRef": receipt.get("paymentRef"),
            "etaMinutes": self.eta_minutes,
        }
        if "deliverTo" in invoice:
            commitment["deliverTo"] = invoice["deliverTo"]
        # Same canonical-sign machinery as the invoice: the commitment is a
        # signed document, verifiable against the merchant card.
        return {"commitment": commitment, "signature": sign_invoice(commitment, self.key)}


def load_or_create_key(path: str | os.PathLike[str]) -> Ed25519PrivateKey:
    """A persistent merchant identity: raw Ed25519 private key bytes on disk
    (the volume), created on first boot — so the buyer's one-time trust
    decision survives restarts."""
    from pathlib import Path

    p = Path(path)
    if p.exists():
        return Ed25519PrivateKey.from_private_bytes(p.read_bytes())
    key = Ed25519PrivateKey.generate()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(key.private_bytes_raw())
    os.chmod(p, 0o600)
    return key

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Adapt household-identity wallet bundles to the production policy's input.

The wallets hand the LLM `{token, membership}` bundles; the `family_spend_prod`
policy reads the `ProdSpendInput` contract.
This adapter bridges the two, in three steps:

- **Decode** each wallet `token` (a compact JWS) into `claims`, pairing it as
  `{jws: token, claims}`. The policy verifies the `jws` independently, so
  decoding here adds no trust.
- **Normalize money.** The float-dollar `amount` becomes integer
  `amountCents` via ``Decimal`` — on *both* the request VC's
  `…requests.amount` and the native call `arguments`, identically, so the
  policy's field-by-field call-binding compares like with like.
- **Harvest** the inline membership from each bundle into a per-call lookup
  keyed by signer DID, reconciling the wallets' inline-attachment with the
  fetch plan's `wallet`-sourced membership fields. Combined with the did:web
  resolver, this yields the membership-with-`adminKey` the policy reads.

The nested `vc.credentialSubject.requests` path is specific to household-
identity's ActionRequest shape — this adapter *is* that bridge, not a generic
transform.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from .didweb import DidResolutionError, DidWebResolver
from .fetchplan import FetchError, WalletLookup
from .types import CallRequest


def _unqualified_action(tool_name: str) -> str:
    return tool_name.split("__", 1)[1] if "__" in tool_name else tool_name


def _coerce_bundle(value: Any) -> dict[str, Any] | None:
    """A `{token, …}` bundle, tolerating a JSON-stringified object (some
    LLM/MCP-client paths stringify object-typed tool results)."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return None
    if isinstance(value, dict) and isinstance(value.get("token"), str):
        return value
    return None


class WalletBundleError(Exception):
    """An LLM-supplied credential bundle could not be decoded.

    Corrupted tokens happen in practice — an LLM that *retypes* a compact JWS
    between tool calls can substitute homoglyphs (observed: Cyrillic ``Р`` for
    Latin ``P``). That is malformed evidence, so it must surface as a clean
    denial with an actionable reason, never as a traceback out of the call
    handler.
    """


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    """Decode (not verify) a compact JWS payload into its claims dict."""
    parts = token.split(".")
    if len(parts) != 3:
        raise WalletBundleError(
            "credential token is not a compact JWS (expected three dot-separated segments)"
        )
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except ValueError as e:
        raise WalletBundleError(
            f"credential token payload is not valid base64url/JSON ({e}); "
            "pass the token exactly as the wallet returned it — "
            "do not retype or reconstruct it"
        ) from e
    if not isinstance(claims, dict):
        # A payload of `[]`, `"text"` or `5` is valid JSON but not a claims
        # set. Every caller reads it with .get, so let it through and the
        # AttributeError surfaces as a traceback instead of a denial.
        raise WalletBundleError(
            "credential token payload is a JSON "
            f"{type(claims).__name__}, not an object of claims"
        )
    return claims


def _dig(obj: Any, *path: str) -> Any:
    """Walk a nested path, stopping at anything that is not a dict.

    The claims are decoded, not verified, so every level is whatever the
    caller put there: `{"vc": "notadict"}` decodes fine and must not raise.
    """
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _normalize_money(obj: dict[str, Any], money_fields: tuple[str, ...]) -> None:
    """In place: each float-dollar ``<field>`` becomes integer ``<field>Cents``."""
    for f in money_fields:
        if f in obj and isinstance(obj[f], (int, float)) and not isinstance(obj[f], bool):
            cents = int((Decimal(str(obj.pop(f))) * 100).to_integral_value(ROUND_HALF_UP))
            obj[f + "Cents"] = cents


@dataclass
class AdaptedCall:
    """The product of adapting a call: the policy envelope's call-sourced
    fields, plus the memberships harvested from the bundles (pre-``adminKey``)."""

    envelope: dict[str, Any]
    memberships: dict[str, dict[str, Any]] = field(default_factory=dict)


class WalletBundleAdapter:
    """Turn a call carrying `{token, membership}` bundles into the policy input.

    ``request_field`` / ``authorization_field`` are the **wire** names — the
    argument keys the LLM supplies on the tool call (and that get stripped
    before the downstream forward). ``request_input_field`` /
    ``authorization_input_field`` are the **policy** names — the closed-input
    fields the fetch plan reads. They coincide by default; a deployment whose
    wire vocabulary predates the policy's (e.g. ``vc_request`` on the wire,
    ``requestVC`` in the policy) sets them apart.
    """

    def __init__(
        self,
        *,
        request_field: str = "requestVC",
        authorization_field: str = "authorizationVC",
        request_input_field: str = "requestVC",
        authorization_input_field: str = "authorizationVC",
        money_fields: tuple[str, ...] = ("amount",),
        tool_action: Callable[[str], str] = _unqualified_action,
    ) -> None:
        self.request_field = request_field
        self.authorization_field = authorization_field
        self.request_input_field = request_input_field
        self.authorization_input_field = authorization_input_field
        self.money_fields = money_fields
        self._tool_action = tool_action

    def adapt(self, request: CallRequest) -> AdaptedCall:
        args = dict(request.arguments)
        req_bundle = _coerce_bundle(args.pop(self.request_field, None))
        auth_bundle = _coerce_bundle(args.pop(self.authorization_field, None))

        # remaining args are the tool's native arguments — normalize money
        _normalize_money(args, self.money_fields)
        envelope: dict[str, Any] = {
            "tool": self._tool_action(request.tool_name),
            "arguments": args,
        }
        memberships: dict[str, dict[str, Any]] = {}

        if req_bundle is not None:
            envelope[self.request_input_field] = self._to_vc(
                req_bundle, normalize_request=True
            )
            self._harvest(req_bundle, memberships)
        if auth_bundle is not None:
            envelope[self.authorization_input_field] = self._to_vc(
                auth_bundle, normalize_request=False
            )
            self._harvest(auth_bundle, memberships)

        return AdaptedCall(envelope=envelope, memberships=memberships)

    def _to_vc(self, bundle: dict[str, Any], *, normalize_request: bool) -> dict[str, Any]:
        token = bundle["token"]
        claims = _decode_jwt_claims(token)
        if normalize_request:
            requests = _dig(claims, "vc", "credentialSubject", "requests")
            if isinstance(requests, dict):
                _normalize_money(requests, self.money_fields)
        return {"jws": token, "claims": claims}

    def _harvest(self, bundle: dict[str, Any], into: dict[str, dict[str, Any]]) -> None:
        membership_token = bundle.get("membership")
        if not isinstance(membership_token, str):
            return
        claims = _decode_jwt_claims(membership_token)
        subject = claims.get("sub")
        if isinstance(subject, str):
            into[subject] = {"jws": membership_token, "claims": claims}


def make_membership_lookup(
    memberships: dict[str, dict[str, Any]], resolver: DidWebResolver
) -> WalletLookup:
    """The `wallet` lookup the fetch plan needs: a harvested membership by
    subject DID, enriched with its admin's resolved key."""

    async def lookup(subject: str) -> dict[str, Any] | None:
        membership = memberships.get(subject)
        if membership is None:
            return None
        try:
            return await resolver.attach_admin_key(membership)
        except DidResolutionError as e:
            # This lookup is a fetch-plan source, so an unreachable or
            # malformed did:web document is a FetchError -- the one failure
            # the filter renders as a denial. Raised as itself it escaped the
            # filter entirely and reached the LLM as an httpx traceback.
            raise FetchError(f"admin DID document could not be resolved: {e}") from e

    return lookup

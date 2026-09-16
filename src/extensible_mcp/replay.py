# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Spending signed evidence, so one approval authorizes one call.

A policy over signed evidence is a pure function of that evidence and the
call. Re-submit the same credentials with the same arguments and it decides
the same way — every signature still verifies, every binding still holds, and
the call goes through again. One human approval, unlimited identical calls.
Nothing inside a stateless policy can prevent that: the evidence has to be
*spent*, and spending is state the policy does not have.

The key is the credential's own ``jti``. It sits inside the signed payload, so
a caller cannot vary it without invalidating the signature — which is what
makes it usable as a replay key, and is exactly what a challenge derived
purely from the terms lacks.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import Any

from .types import CallFilterResult, CallRequest
from .wallet_bundle import _coerce_bundle, _decode_jwt_claims

# A generous default: the bound exists so a long-running proxy cannot be grown
# without limit by calls carrying fresh credentials, not to ration real use.
DEFAULT_MAX_ENTRIES = 16384


def wallet_bundle_jti(value: Any) -> str | None:
    """The ``jti`` of a wallet ``{token, membership}`` bundle's credential.

    Returns ``None`` when the value is not a bundle at all — that is not this
    filter's business, and the policy filter will refuse it on its own terms.
    A bundle whose credential carries no ``jti`` also returns ``None``, which
    the caller treats as unspendable rather than as absent.
    """
    bundle = _coerce_bundle(value)
    if bundle is None:
        return None
    try:
        claims = _decode_jwt_claims(bundle["token"])
    except Exception:  # noqa: BLE001 - malformed evidence is the policy's to refuse
        return None
    jti = claims.get("jti")
    return jti if isinstance(jti, str) and jti else None


def _credential_expiry(value: Any) -> float | None:
    """The credential's own ``exp``, if it has a usable one."""
    bundle = _coerce_bundle(value)
    if bundle is None:
        return None
    try:
        claims = _decode_jwt_claims(bundle["token"])
    except Exception:  # noqa: BLE001
        return None
    exp = claims.get("exp")
    return float(exp) if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None


class SingleUseEvidenceFilter:
    """Wrap a call filter so each piece of signed evidence authorizes one call.

    Wraps the policy filter rather than sitting beside it in the pipeline, for
    two reasons that both matter:

    - the policy filter strips credential fields from the arguments it passes
      on, so a filter placed after it never sees the evidence at all;
    - evidence must be spent only when the call was actually authorized. A
      guard that recorded on arrival would let a call the policy refuses burn
      the human's approval — an LLM that gets the amount wrong once would send
      them back to the wallet.

    Records nothing on a denial, so a refused call leaves the credential
    spendable. It does record before the call is dispatched, so a downstream
    that fails after the policy allowed it has still spent the evidence: the
    conservative direction, since the proxy cannot know whether the downstream
    acted.

    The store is in memory and per process. That is the same scope as
    ``DiscoveredToolsFilter``'s, and it means a restart forgets what has been
    spent; a deployment that needs replay protection across restarts or across
    several proxies should pass a shared store instead of relying on this.
    """

    def __init__(
        self,
        inner: Any,
        *,
        credential_fields: Sequence[str] = ("requestVC",),
        extract_id: Callable[[Any], str | None] = wallet_bundle_jti,
        clock: Callable[[], float] = time.time,
        default_ttl_seconds: float = 3600.0,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        self._inner = inner
        self._credential_fields = tuple(credential_fields)
        self._extract_id = extract_id
        self._clock = clock
        self._default_ttl_seconds = default_ttl_seconds
        self._max_entries = max_entries
        # id -> the time after which the entry may be forgotten, which is the
        # credential's own expiry: past it the policy refuses the credential
        # anyway, so remembering it buys nothing.
        self._spent: dict[str, float] = {}

    @property
    def bundle(self) -> Any:
        """Delegate, so a router that reads ``filter.bundle`` still works."""
        return getattr(self._inner, "bundle", None)

    def _prune(self, now: float) -> None:
        expired = [k for k, exp in self._spent.items() if exp <= now]
        for k in expired:
            del self._spent[k]

    async def check(self, request: CallRequest) -> CallFilterResult:
        now = self._clock()
        self._prune(now)

        present = [f for f in self._credential_fields if f in request.arguments]
        ids: list[tuple[str, float]] = []
        for field in present:
            value = request.arguments[field]
            cid = self._extract_id(value)
            if cid is None:
                # A credential field is here but carries nothing spendable. Let
                # the inner filter judge the evidence itself -- if it somehow
                # allows an unspendable credential, refuse rather than admit
                # something that could then be replayed freely.
                inner = await self._inner.check(request)
                if not inner.allowed:
                    return inner
                return self._deny(
                    request,
                    f"the credential in {field!r} carries no 'jti', so it cannot be "
                    "marked as used; evidence must be single-use",
                    inner.arguments,
                )
            exp = _credential_expiry(value)
            ids.append((cid, exp if exp is not None else now + self._default_ttl_seconds))

        for cid, _ in ids:
            if cid in self._spent:
                return self._deny(
                    request,
                    "that approval has already been used. A signed approval "
                    "authorizes one call; ask for a new one rather than "
                    "re-sending this one.",
                )

        if ids and len(self._spent) + len(ids) > self._max_entries:
            # Evicting a live entry to make room would let a replay through, so
            # refuse instead. Reaching this means the proxy is being driven far
            # harder than a human-approval rail implies.
            return self._deny(
                request,
                "the proxy cannot currently guarantee this approval has not "
                "already been used, so it is refusing the call.",
            )

        result = await self._inner.check(request)
        if result.allowed:
            for cid, exp in ids:
                self._spent[cid] = exp
        return result

    def _deny(
        self,
        request: CallRequest,
        reason: str,
        arguments: dict[str, Any] | None = None,
    ) -> CallFilterResult:
        if arguments is None:
            # Strip every field the governing bundle counts as a credential,
            # not merely the ones this filter guards -- otherwise a denial
            # here would carry evidence forward that the policy filter would
            # have removed.
            bundle = self.bundle
            credential_fields = set(self._credential_fields)
            if bundle is not None:
                credential_fields |= set(bundle.credential_fields())
            arguments = {
                k: v for k, v in request.arguments.items()
                if k not in credential_fields
            }
        return CallFilterResult(
            allowed=False,
            reason=reason,
            tool_name=request.tool_name,
            arguments=arguments,
        )

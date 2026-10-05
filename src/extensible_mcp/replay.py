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
from typing import Any, Protocol

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


# Reserve outcomes. Strings rather than a bool so the two refusals keep their
# distinct explanations: one is the caller's to fix by getting a new approval,
# the other is ours and says so.
RESERVED = "reserved"
ALREADY_SPENT = "already-spent"
AT_CAPACITY = "at-capacity"


class SpentStore(Protocol):
    """Where spent evidence is remembered.

    ``reserve`` **must be atomic**: test and set in one step, with no await
    between them. That is the whole contract, and it is the reason this is not
    a "have I seen this?" query plus a separate write -- two concurrent calls
    carrying one credential would both pass such a query before either wrote.

    A shared implementation (Redis ``SET key val NX PX``, a conditional insert)
    gives replay protection across restarts and across several proxies. The
    in-memory default gives it within one process only.
    """

    async def reserve(self, key: str, expires_at: float) -> str:
        """Claim ``key`` until ``expires_at``. One of the three outcomes above."""
        ...

    async def release(self, key: str) -> None:
        """Hand back a reservation whose call the policy then refused."""
        ...


class InMemorySpentStore:
    """The default: a bounded dict, per process.

    Refuses at capacity rather than evicting, because evicting a live entry to
    make room is precisely how a replay gets through -- so the bound pushes
    back on new work instead of forgetting old work.
    """

    def __init__(
        self,
        *,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._max_entries = max_entries
        self._clock = clock
        # id -> the time after which the entry may be forgotten, which is the
        # credential's own expiry: past it the policy refuses the credential
        # anyway, so remembering it buys nothing.
        self._spent: dict[str, float] = {}

    def prune(self, now: float) -> None:
        for key in [k for k, exp in self._spent.items() if exp <= now]:
            del self._spent[key]

    def __len__(self) -> int:
        return len(self._spent)

    async def reserve(self, key: str, expires_at: float) -> str:
        # Every statement here is synchronous on purpose. No await between the
        # membership test and the insert means the pair cannot interleave with
        # another task on this event loop.
        self.prune(self._clock())
        if key in self._spent:
            return ALREADY_SPENT
        if len(self._spent) >= self._max_entries:
            return AT_CAPACITY
        self._spent[key] = expires_at
        return RESERVED

    async def release(self, key: str) -> None:
        self._spent.pop(key, None)


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

    **Reserved before the policy runs, released if the policy refuses.** An
    earlier version tested the store, awaited the policy, and recorded
    afterwards. Two concurrent calls carrying one credential therefore both
    passed the test before either recorded, and one approval authorized both --
    the replay this filter exists to prevent, reached by concurrency rather
    than by sequence. Reserving first closes that while keeping a refused
    call's credential spendable. The cost is one narrow false denial: of two
    concurrent calls on a single credential, the one that loses the race is
    told the approval is used even if the winner is then refused and releases
    it. Refusing wrongly is the safe direction and a retry succeeds.

    The default store is in memory and per process, the same scope as
    ``DiscoveredToolsFilter``'s, so a restart forgets what has been spent and
    two proxies do not share it. Pass ``store=`` with a shared implementation
    for replay protection across either; the contract is that ``reserve`` is
    atomic.
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
        store: SpentStore | None = None,
    ) -> None:
        self._inner = inner
        self._credential_fields = tuple(credential_fields)
        self._extract_id = extract_id
        self._clock = clock
        self._default_ttl_seconds = default_ttl_seconds
        # `store or ...` would be wrong: InMemorySpentStore defines __len__, so
        # an empty store is falsy -- and a store is always empty when it is
        # handed in, which would silently discard every injected one.
        self._store: SpentStore = (
            store
            if store is not None
            else InMemorySpentStore(max_entries=max_entries, clock=clock)
        )

    @property
    def bundle(self) -> Any:
        """Delegate, so a router that reads ``filter.bundle`` still works."""
        return getattr(self._inner, "bundle", None)

    async def check(self, request: CallRequest) -> CallFilterResult:
        now = self._clock()

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

        # Claim every id before the policy runs. A partial claim is rolled back,
        # so a refused reservation never leaves half of this call's credentials
        # held against a call that is not going to happen.
        held: list[str] = []
        for cid, exp in ids:
            outcome = await self._store.reserve(cid, exp)
            if outcome != RESERVED:
                await self._release(held)
                if outcome == ALREADY_SPENT:
                    return self._deny(
                        request,
                        "that approval has already been used. A signed approval "
                        "authorizes one call; ask for a new one rather than "
                        "re-sending this one.",
                    )
                return self._deny(
                    request,
                    "the proxy cannot currently guarantee this approval has not "
                    "already been used, so it is refusing the call.",
                )
            held.append(cid)

        try:
            result = await self._inner.check(request)
        except BaseException:
            # The policy faulted rather than decided, so the evidence was never
            # used against anything. Hand it back.
            await self._release(held)
            raise
        if not result.allowed:
            await self._release(held)
        return result

    async def _release(self, keys: Sequence[str]) -> None:
        for key in keys:
            await self._store.release(key)

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

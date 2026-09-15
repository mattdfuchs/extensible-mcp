# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Shadow-mode call filter: a differential regression tool for swapping enforcers.

Wraps the *primary* filter (the authority — today the hand-coded
``VCCallFilter``) and runs a *shadow* filter (the supplied-bundle
``VCPolicyFilter``) alongside it on the same call. The primary's verdict is the
only one that gates the call; the shadow is observed, compared, classified, and
recorded, but can never allow, deny, or break a call.

**What this is, and what it is not (2026-07-17).** This is a *regression test*:
it measures where two enforcers disagree on the traffic it happens to see, so
it is only as complete as that traffic sample — it needs a representative test
set to mean anything, and it cannot prove a property over the whole input space.

It earns its keep exactly when one side is **unformalized** — here, the
incumbent is hand-coded Python with no Lean ``Prop``, so "is the replacement a
faithful tightening?" cannot be *proven*, only *observed*. The same holds for
any rule set not proven against the incumbent (third-party Rego, Cedar, ad-hoc code).

For a revision between two proven policies, the harness is *not* the right tool for the
tightening question: both sides are Lean ``Prop``s over a shared input type, so
``B.allow → A.allow`` is a theorem discharged once over *all* inputs (composed
with the two faithfulness theorems), which strictly dominates a traffic sample.
There the harness demotes to an optional smoke test on the *runtime glue* (the
adapter / fetchplan / resolver seams the proof does not cover), never the gate.

So treat the ``clean`` summary below as the **cutover gate for this specific
migration** (unformalized incumbent, reviewed to be a strict tightening) — not
as a universal requirement. A migration that deliberately *loosens* would
respecify which divergences are expected; ``new-allow`` would not be a red flag
there.

The point is to measure, on the sampled traffic, *where the two disagree*. Two
rules (under the strict-tightening assumption this migration was reviewed for):

- **primary DENY, shadow ALLOW** is an unconditional red flag: the new policy is
  *weaker* than the one it replaces, which must never happen under a migration
  that is supposed to be a strict tightening. It signals a correctness bug.
- **primary ALLOW, shadow DENY** is a *triage* item, not automatically good. The
  new policy is stricter here — but "stricter" can mean either it caught
  something the old filter missed (a genuine tightening) *or* it rejected
  legitimate current traffic because the vocabularies/shapes don't line up yet
  (e.g. the policy wants role ``"kid"`` but the wallets issue ``"child"``, or it
  binds a ``merchant`` field the request VCs don't carry). Allow→deny divergences
  are bucketed by the shadow's deny reason so a human can tell those apart.

A shadow that raises is recorded as a ``shadow-error`` (also a red flag —
the replacement engine faulted) and the primary result is still returned.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass, field

from extensible_mcp import CallFilterResult, CallRequest

logger = logging.getLogger("extensible_mcp_vc.shadow")


def jsonl_sink(path: str) -> "Callable[[ShadowRecord], None]":
    """A ``sink`` that appends each record as one JSON line at ``path`` —
    the durable divergence log the cutover review reads."""

    def sink(record: "ShadowRecord") -> None:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(record)) + "\n")

    return sink


# Substring signatures over the policy's ``deny_reason`` strings, so an
# allow→deny divergence can be bucketed by *what* the new policy objected to.
# Order matters only for readability; a reason may land in several buckets.
_BUCKET_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("signature", "signature is invalid"),
    ("window", "outside its validity window"),
    ("role", "role =="),
    ("call-binding", "amountCents == input.arguments"),
    ("call-binding", "merchant == input.arguments"),
    ("amount-tier", "amountCents <= 1000"),
    ("amount-tier", "1000 < input"),
    ("amount-tier", "amountCents <= 20000"),
    ("membership", "trusted admin"),
    ("auth-binding", "authorizes_request =="),
    ("auth-binding", "not bound"),
)


def classify_reason(reason: str | None) -> tuple[str, ...]:
    """Bucket a shadow deny reason by matching known policy-reason signatures.

    Returns the distinct buckets the reason matches, or ``("other",)`` when it
    matches none — an *unrecognized* new denial, which deserves a closer look
    because it isn't one of the tightenings the migration anticipated.
    """
    if not reason:
        return ("other",)
    hits: list[str] = []
    for bucket, needle in _BUCKET_SIGNATURES:
        if needle in reason and bucket not in hits:
            hits.append(bucket)
    return tuple(hits) if hits else ("other",)


@dataclass
class ShadowRecord:
    """One call observed through the harness."""

    tool_name: str
    direction: str  # "agree" | "new-deny" | "new-allow" | "shadow-error"
    primary_allowed: bool
    shadow_allowed: bool | None  # None on shadow-error
    primary_reason: str | None = None
    shadow_reason: str | None = None
    shadow_error: str | None = None
    buckets: tuple[str, ...] = ()

    @property
    def is_red_flag(self) -> bool:
        """A divergence that blocks cutover on its own: the replacement is
        weaker (``new-allow``) or it faulted (``shadow-error``). Allow→deny
        (``new-deny``) is deliberately *not* auto-flagged — it is triaged by
        ``buckets``."""
        return self.direction in ("new-allow", "shadow-error")


class ShadowCallFilter:
    """A ``CallFilter`` that gates on ``primary`` and merely observes ``shadow``.

    Append-only: every call produces one :class:`ShadowRecord` in ``records``
    (and is handed to ``sink`` if supplied). The returned :class:`CallFilterResult`
    is *always* the primary's, verbatim.
    """

    def __init__(
        self,
        primary,
        shadow,
        *,
        sink: Callable[[ShadowRecord], None] | None = None,
    ) -> None:
        self.primary = primary
        self.shadow = shadow
        self._sink = sink
        self._records: list[ShadowRecord] = []

    async def check(self, request: CallRequest) -> CallFilterResult:
        primary_result = await self.primary.check(request)
        record = await self._observe(request, primary_result)
        self._records.append(record)
        if self._sink is not None:
            self._sink(record)
        self._log(record)
        return primary_result

    async def _observe(
        self, request: CallRequest, primary_result: CallFilterResult
    ) -> ShadowRecord:
        try:
            shadow_result = await self.shadow.check(request)
        except Exception as e:  # the shadow must never break a call
            return ShadowRecord(
                tool_name=request.tool_name,
                direction="shadow-error",
                primary_allowed=primary_result.allowed,
                shadow_allowed=None,
                primary_reason=primary_result.reason,
                shadow_error=f"{type(e).__name__}: {e}",
            )

        if primary_result.allowed == shadow_result.allowed:
            direction = "agree"
        elif primary_result.allowed and not shadow_result.allowed:
            direction = "new-deny"
        else:
            direction = "new-allow"

        buckets = (
            classify_reason(shadow_result.reason)
            if direction == "new-deny"
            else ()
        )
        return ShadowRecord(
            tool_name=request.tool_name,
            direction=direction,
            primary_allowed=primary_result.allowed,
            shadow_allowed=shadow_result.allowed,
            primary_reason=primary_result.reason,
            shadow_reason=shadow_result.reason,
            buckets=buckets,
        )

    def _log(self, r: ShadowRecord) -> None:
        if r.direction == "agree":
            logger.debug("[SHADOW] agree on %r (allowed=%s)", r.tool_name, r.primary_allowed)
        elif r.direction == "new-deny":
            logger.info(
                "[SHADOW] new-deny on %r — primary allowed, policy would deny "
                "%s: %s",
                r.tool_name, list(r.buckets), r.shadow_reason,
            )
        elif r.direction == "new-allow":
            logger.warning(
                "[SHADOW] ⚠ RED FLAG new-allow on %r — policy is WEAKER than "
                "primary (primary denied: %s)",
                r.tool_name, r.primary_reason,
            )
        else:  # shadow-error
            logger.warning(
                "[SHADOW] ⚠ RED FLAG shadow-error on %r — replacement engine "
                "faulted: %s",
                r.tool_name, r.shadow_error,
            )

    @property
    def records(self) -> list[ShadowRecord]:
        return list(self._records)

    def summary(self) -> ShadowSummary:
        """Aggregate the observations into a cutover-readiness report."""
        return ShadowSummary.from_records(self._records)


@dataclass
class ShadowSummary:
    total: int = 0
    agree: int = 0
    new_deny: int = 0
    new_allow: int = 0
    shadow_error: int = 0
    bucket_counts: dict[str, int] = field(default_factory=dict)
    red_flags: list[ShadowRecord] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        """True when nothing blocks cutover *on its own*. Allow→deny
        divergences still need human triage (see ``new_deny`` / ``bucket_counts``),
        but a clean summary means no weaker-than-primary or faulting cases."""
        return not self.red_flags

    @classmethod
    def from_records(cls, records: list[ShadowRecord]) -> "ShadowSummary":
        s = cls(total=len(records))
        for r in records:
            if r.direction == "agree":
                s.agree += 1
            elif r.direction == "new-deny":
                s.new_deny += 1
                for b in r.buckets:
                    s.bucket_counts[b] = s.bucket_counts.get(b, 0) + 1
            elif r.direction == "new-allow":
                s.new_allow += 1
            else:
                s.shadow_error += 1
            if r.is_red_flag:
                s.red_flags.append(r)
        return s

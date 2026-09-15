# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the shadow-mode harness mechanism (stub filters, no crypto).

These pin the harness's guarantees independent of the real filters: the primary
is always the authority, the shadow can never break a call, and divergences are
detected, classified, and reported correctly. The real-filter behaviour lives in
``test_shadow_integration.py``."""

from __future__ import annotations

import pytest
from extensible_mcp import CallFilterResult, CallRequest

from extensible_mcp_vc.shadow import (
    ShadowCallFilter,
    classify_reason,
)


class _Stub:
    """A CallFilter that returns a canned verdict (or raises)."""

    def __init__(self, allowed, reason=None, *, raises=None, arguments=None):
        self._allowed = allowed
        self._reason = reason
        self._raises = raises
        self._arguments = arguments

    async def check(self, request: CallRequest) -> CallFilterResult:
        if self._raises is not None:
            raise self._raises
        return CallFilterResult(
            allowed=self._allowed,
            reason=self._reason,
            tool_name=request.tool_name,
            arguments=self._arguments
            if self._arguments is not None
            else request.arguments,
        )


def _call(args=None):
    return CallRequest(
        tool_name="payments__spend",
        arguments=args if args is not None else {"amount": 5.0},
        server_name="payments",
    )


# --- classification ---------------------------------------------------------

@pytest.mark.parametrize(
    "reason, expected",
    [
        ('required: input.requesterMembership.claims.vc.credentialSubject.role == "kid"', ("role",)),
        ("required: ...requests.merchant == input.arguments.merchant", ("call-binding",)),
        ("required: ...requests.amountCents == input.arguments.amountCents", ("call-binding",)),
        ("required: ...amountCents <= 1000", ("amount-tier",)),
        ("a credential signature is invalid", ("signature",)),
        ("a credential is outside its validity window", ("window",)),
        ("a membership credential does not chain to a trusted admin", ("membership",)),
        ("the authorization is not bound to this request", ("auth-binding",)),
        ("something nobody anticipated", ("other",)),
        (None, ("other",)),
    ],
)
def test_classify_reason_buckets(reason, expected):
    assert classify_reason(reason) == expected


def test_classify_reason_multi_bucket():
    reason = (
        'required: role == "kid"; '
        "required: ...merchant == input.arguments.merchant"
    )
    assert set(classify_reason(reason)) == {"role", "call-binding"}


# --- authority: primary result is always returned verbatim ------------------

async def test_returns_primary_result_when_shadow_agrees():
    h = ShadowCallFilter(_Stub(True), _Stub(True))
    result = await h.check(_call())
    assert result.allowed is True


async def test_primary_authority_preserved_on_divergence():
    # shadow denies, but the harness must still forward the primary's ALLOW
    primary = _Stub(True, arguments={"amount": 5.0, "stripped": "yes"})
    h = ShadowCallFilter(primary, _Stub(False, "policy says no"))
    result = await h.check(_call())
    assert result.allowed is True
    assert result.arguments == {"amount": 5.0, "stripped": "yes"}


async def test_primary_deny_is_forwarded_even_if_shadow_allows():
    h = ShadowCallFilter(_Stub(False, "primary denied"), _Stub(True))
    result = await h.check(_call())
    assert result.allowed is False
    assert result.reason == "primary denied"


# --- divergence detection & direction ---------------------------------------

async def test_agree_records_no_divergence():
    h = ShadowCallFilter(_Stub(True), _Stub(True))
    await h.check(_call())
    (rec,) = h.records
    assert rec.direction == "agree"
    assert rec.is_red_flag is False


async def test_new_deny_is_triage_not_red_flag():
    h = ShadowCallFilter(
        _Stub(True),
        _Stub(False, 'required: role == "kid"'),
    )
    await h.check(_call())
    (rec,) = h.records
    assert rec.direction == "new-deny"
    assert rec.buckets == ("role",)
    assert rec.is_red_flag is False  # allow->deny is triaged, not auto-blocking


async def test_new_allow_is_red_flag():
    # primary denied, shadow allowed -> replacement is WEAKER
    h = ShadowCallFilter(_Stub(False, "primary denied"), _Stub(True))
    await h.check(_call())
    (rec,) = h.records
    assert rec.direction == "new-allow"
    assert rec.is_red_flag is True


# --- shadow isolation -------------------------------------------------------

async def test_shadow_exception_never_breaks_the_call():
    primary = _Stub(True)
    h = ShadowCallFilter(primary, _Stub(True, raises=RuntimeError("boom")))
    result = await h.check(_call())  # must not raise
    assert result.allowed is True
    (rec,) = h.records
    assert rec.direction == "shadow-error"
    assert "boom" in rec.shadow_error
    assert rec.is_red_flag is True


# --- sink & summary ---------------------------------------------------------

async def test_sink_is_called_per_record():
    seen = []
    h = ShadowCallFilter(_Stub(True), _Stub(True), sink=seen.append)
    await h.check(_call())
    await h.check(_call())
    assert len(seen) == 2


async def test_summary_aggregates_directions_and_buckets():
    h = ShadowCallFilter(_Stub(True), _Stub(True))
    # drive a mix through by swapping the shadow between calls
    await h.check(_call())  # agree
    h.shadow = _Stub(False, 'required: role == "kid"')
    await h.check(_call())  # new-deny role
    h.shadow = _Stub(False, "required: ...merchant == input.arguments.merchant")
    await h.check(_call())  # new-deny call-binding
    h.primary, h.shadow = _Stub(False, "x"), _Stub(True)
    await h.check(_call())  # new-allow (red flag)

    s = h.summary()
    assert s.total == 4
    assert s.agree == 1
    assert s.new_deny == 2
    assert s.new_allow == 1
    assert s.bucket_counts == {"role": 1, "call-binding": 1}
    assert len(s.red_flags) == 1
    assert s.clean is False


async def test_summary_clean_when_only_agreements_and_triaged_denies():
    h = ShadowCallFilter(_Stub(True), _Stub(False, 'required: role == "kid"'))
    await h.check(_call())
    s = h.summary()
    assert s.new_deny == 1
    assert s.clean is True  # allow->deny alone does not block cutover

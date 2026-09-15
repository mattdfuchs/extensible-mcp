# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests for the reference PriceTierCallFilter shipped in examples/."""

from __future__ import annotations

import sys
from pathlib import Path

from extensible_mcp import CallRequest

# Make examples/ importable like proxy_server.py does in production
_EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
sys.path.insert(0, str(_EXAMPLES))
from price_tier_filter import PriceTierCallFilter  # noqa: E402


def _pizza_call(total: float, *, authorization_verified: bool | None = None):
    args: dict = {
        "pizza_type": "large pepperoni",
        "store": "Dominos",
        "address": "123 Main St",
        "quantity": 1,
        "total": total,
    }
    if authorization_verified is not None:
        args["_verified_vcs"] = {
            "request": True,
            "authorization": authorization_verified,
        }
    return CallRequest(
        tool_name="pizza__order_pizza", arguments=args, server_name="pizza"
    )


class TestPriceTierCallFilter:
    def _filter(self):
        return PriceTierCallFilter(
            tools=["pizza__order_pizza"],
            total_field="total",
            hard_cap=200.0,
            parent_required_above=10.0,
        )

    async def test_under_threshold_passes_without_parent_vc(self):
        filt = self._filter()
        result = await filt.check(_pizza_call(9.0, authorization_verified=False))
        assert result.allowed, result.reason
        assert "_verified_vcs" not in result.arguments  # stripped
        assert result.arguments["total"] == 9.0

    async def test_over_threshold_without_parent_vc_is_rejected(self):
        filt = self._filter()
        result = await filt.check(_pizza_call(15.0, authorization_verified=False))
        assert not result.allowed
        assert "parent" in result.reason.lower()

    async def test_over_threshold_with_parent_vc_passes(self):
        filt = self._filter()
        result = await filt.check(_pizza_call(15.0, authorization_verified=True))
        assert result.allowed, result.reason
        assert "_verified_vcs" not in result.arguments

    async def test_over_hard_cap_is_rejected_even_with_parent_vc(self):
        filt = self._filter()
        result = await filt.check(_pizza_call(220.0, authorization_verified=True))
        assert not result.allowed
        assert "$200" in result.reason

    async def test_at_exactly_the_parent_threshold_passes_without_parent(self):
        """Threshold is strict (>): exactly $10.00 doesn't need the parent."""
        filt = self._filter()
        result = await filt.check(_pizza_call(10.0, authorization_verified=False))
        assert result.allowed, result.reason

    async def test_at_exactly_the_hard_cap_passes_with_parent(self):
        """Hard cap is strict (>): exactly $200.00 still goes through."""
        filt = self._filter()
        result = await filt.check(_pizza_call(200.0, authorization_verified=True))
        assert result.allowed, result.reason

    async def test_missing_total_field_is_rejected(self):
        filt = self._filter()
        request = CallRequest(
            tool_name="pizza__order_pizza",
            arguments={"pizza_type": "x", "store": "Dominos", "address": "y"},
            server_name="pizza",
        )
        result = await filt.check(request)
        assert not result.allowed
        assert "total" in result.reason

    async def test_non_numeric_total_is_rejected(self):
        filt = self._filter()
        request = CallRequest(
            tool_name="pizza__order_pizza",
            arguments={
                "pizza_type": "x",
                "store": "Dominos",
                "address": "y",
                "total": "fifteen",
            },
            server_name="pizza",
        )
        result = await filt.check(request)
        assert not result.allowed
        assert "non-numeric" in result.reason

    async def test_non_matching_tool_passes_through(self):
        filt = self._filter()
        request = CallRequest(
            tool_name="payments__balance",
            arguments={"anything": "goes"},
            server_name="payments",
        )
        result = await filt.check(request)
        assert result.allowed
        assert result.arguments == {"anything": "goes"}

    async def test_fnmatch_patterns_match(self):
        filt = PriceTierCallFilter(
            tools=["pizza__*"],
            total_field="total",
            hard_cap=200.0,
            parent_required_above=10.0,
        )
        result = await filt.check(_pizza_call(5.0, authorization_verified=False))
        assert result.allowed, result.reason

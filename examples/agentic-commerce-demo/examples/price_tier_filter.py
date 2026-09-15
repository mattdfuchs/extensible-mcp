# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Reference policy filter that enforces a price-tiered household rule.

Composes with VCCallFilter (which runs *before* this) so that:

- Orders over the hard cap (default $200) are rejected outright.
- Orders over the parent-approval threshold (default $10) require the
  parent's authorization VC to have been verified.
- Orders at or below the threshold pass with just the kid's request VC.

The filter reads the ``_verified_vcs`` marker that VCCallFilter leaves
in arguments for tools in ``optional_authorization_tools``, then strips
it before forwarding. Tools that aren't price-tier-controlled pass
through untouched.

Plugged into the proxy via ``extra_call_filters`` on
``extensible_mcp_vc.extend_server``.
"""

from __future__ import annotations

import fnmatch
import logging
from typing import Any

from extensible_mcp import CallFilterResult, CallRequest

logger = logging.getLogger("extensible_mcp_vc.price_tier")


class PriceTierCallFilter:
    def __init__(
        self,
        *,
        tools: list[str],
        total_field: str = "total",
        hard_cap: float = 200.0,
        parent_required_above: float = 10.0,
    ) -> None:
        """Build a price-tier filter.

        ``tools`` accepts ``fnmatch`` patterns over qualified tool names.
        ``total_field`` is the name of the float-valued argument that
        carries the order total in dollars.
        ``parent_required_above`` is the threshold over which the
        ``_verified_vcs.authorization`` flag must be true.
        ``hard_cap`` is an absolute reject limit; orders over this fail
        regardless of authorization.
        """
        self._patterns: list[str] = list(tools)
        self._total_field = total_field
        self._hard_cap = hard_cap
        self._parent_threshold = parent_required_above

    def _applies(self, tool_name: str) -> bool:
        return any(fnmatch.fnmatch(tool_name, p) for p in self._patterns)

    async def check(self, request: CallRequest) -> CallFilterResult:
        if not self._applies(request.tool_name):
            return CallFilterResult(
                allowed=True,
                tool_name=request.tool_name,
                arguments=request.arguments,
            )

        args = dict(request.arguments)
        verified = args.pop("_verified_vcs", {}) or {}
        if not isinstance(verified, dict):
            verified = {}

        total_raw = args.get(self._total_field)
        try:
            total = float(total_raw)
        except (TypeError, ValueError):
            logger.warning(
                "[POLICY] ✗ denied %r: missing or non-numeric '%s' field "
                "(got %r)",
                request.tool_name,
                self._total_field,
                total_raw,
            )
            return _deny(
                request,
                f"missing or non-numeric '{self._total_field}' argument; "
                f"the household policy needs a total to decide.",
            )

        if total > self._hard_cap:
            logger.warning(
                "[POLICY] ✗ denied %r: total $%.2f exceeds household cap "
                "$%.2f",
                request.tool_name,
                total,
                self._hard_cap,
            )
            return _deny(
                request,
                f"household policy: orders over ${self._hard_cap:.2f} are "
                f"not permitted (this one is ${total:.2f}).",
            )

        if total > self._parent_threshold and not verified.get("authorization"):
            logger.warning(
                "[POLICY] ✗ denied %r: total $%.2f is over the parent-"
                "approval threshold $%.2f and no verified vc_authorization "
                "was supplied",
                request.tool_name,
                total,
                self._parent_threshold,
            )
            return _deny(
                request,
                (
                    f"household policy: orders over "
                    f"${self._parent_threshold:.2f} require a parent's "
                    f"signed authorization VC. Call "
                    f"`request_authorization_vc` with the bundle you got "
                    f"from `request_action_vc` and pass the result as "
                    f"`vc_authorization`, then retry."
                ),
            )

        logger.info(
            "[POLICY] ✓ %r passes price-tier policy (total=$%.2f, "
            "hard_cap=$%.2f, parent_required_above=$%.2f, "
            "parent_verified=%s)",
            request.tool_name,
            total,
            self._hard_cap,
            self._parent_threshold,
            bool(verified.get("authorization")),
        )
        return CallFilterResult(
            allowed=True, tool_name=request.tool_name, arguments=args
        )


def _deny(request: CallRequest, reason: str) -> CallFilterResult:
    return CallFilterResult(
        allowed=False,
        reason=reason,
        tool_name=request.tool_name,
        arguments=request.arguments,
    )

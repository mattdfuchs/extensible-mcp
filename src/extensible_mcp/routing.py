# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Per-server bundle routing: connect stage-one selection to call-path
enforcement.

A :class:`BundleRouter` does two jobs:

- **Admission (load time).** Given a server's proxy-controlled admission facts,
  it builds a provenance descriptor, runs the :class:`LayeredBundleSelector`,
  and — if a bundle is selected — instantiates that bundle's policy filter and
  registers it for the server. A refused server is not admitted (the caller
  does not connect it). This is the "no default servers / fail closed" rule.

- **Routing (call time).** It is itself a ``CallFilter``: each call is
  dispatched to the :class:`WasmPolicyFilter` registered for the call's server,
  or passed through unchanged if no bundle governs that server. Because it sits
  in the call pipeline, the bundle filter's credential-stripped arguments thread
  forward to the downstream call like any other filter's.

The bundle-name → filter step is deployment-supplied (``filter_factory``): a
bundle's runtime needs trust-root config and a wallet lookup, which are not in
the bundle's own artifacts (those describe the policy, not the deployment). A
factory that returns ``None`` for a selected bundle fails closed — a
named-but-unavailable bundle refuses the server.
"""

from __future__ import annotations

from collections.abc import Callable

from .selection import LayeredBundleSelector, SelectionResult, provenance_descriptor
from .types import CallFilterResult, CallRequest
from .wasm_filter import WasmPolicyFilter

# bundle name -> a configured policy filter (or None if unavailable).
FilterFactory = Callable[[str], "WasmPolicyFilter | None"]


class BundleRouter:
    """Admits servers to bundles and routes calls to the right bundle filter."""

    def __init__(
        self,
        selector: LayeredBundleSelector,
        filter_factory: FilterFactory,
        *,
        default_trust_tier: str = "prod",
    ) -> None:
        self._selector = selector
        self._filter_factory = filter_factory
        self._default_trust_tier = default_trust_tier
        self._filters: dict[str, WasmPolicyFilter] = {}
        self._decisions: dict[str, SelectionResult] = {}

    def admit(
        self,
        *,
        server_name: str,
        url: str | None = None,
        how_loaded: str,
        transport: str | None = None,
        trust_tier: str | None = None,
    ) -> SelectionResult:
        """Decide whether to load ``server_name`` and, if so, register its
        bundle filter. Returns the selection result; the caller connects the
        server only when ``result.allowed``."""
        descriptor = provenance_descriptor(
            origin_server=server_name,
            url=url or "",
            config_trust_tier=trust_tier or self._default_trust_tier,
            how_loaded=how_loaded,
            transport=transport,
        )
        result = self._selector.select(descriptor)

        if result.allowed:
            assert result.bundle is not None
            policy_filter = self._filter_factory(result.bundle)
            if policy_filter is None:
                # Selected a bundle the deployment cannot provide → fail closed.
                result = SelectionResult(
                    None, result.source, f"bundle {result.bundle!r} unavailable"
                )
            else:
                self._filters[server_name] = policy_filter

        self._decisions[server_name] = result
        return result

    def governs(self, server_name: str) -> bool:
        return server_name in self._filters

    def bundle_for(self, server_name: str):
        """The policy bundle governing a server's tools, or ``None``. Lets the
        search-side augmenter surface the same bundle the call path enforces."""
        policy_filter = self._filters.get(server_name)
        return policy_filter.bundle if policy_filter is not None else None

    def decision_for(self, server_name: str) -> SelectionResult | None:
        return self._decisions.get(server_name)

    async def check(self, request: CallRequest) -> CallFilterResult:
        policy_filter = self._filters.get(request.server_name)
        if policy_filter is None:
            # No bundle governs this server — pass through unchanged.
            return CallFilterResult(
                allowed=True,
                tool_name=request.tool_name,
                arguments=request.arguments,
            )
        return await policy_filter.check(request)

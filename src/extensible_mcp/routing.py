# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Per-server bundle routing: connect stage-one selection to call-path
enforcement.

A :class:`BundleRouter` does two jobs:

- **Admission (load time).** Given a server's proxy-controlled admission facts,
  it builds a provenance descriptor, runs the :class:`LayeredBundleSelector`,
  and — if a route is selected — instantiates that route's policy filter and
  registers it for the server. A refused server is not admitted (the caller
  does not connect it). This is the "no default servers / fail closed" rule.

- **Routing (call time).** It is itself a ``CallFilter``: each call is
  dispatched to the :class:`WasmPolicyFilter` registered for the call's server,
  or passed through unchanged if no bundle governs that server. Because it sits
  in the call pipeline, the bundle filter's credential-stripped arguments thread
  forward to the downstream call like any other filter's.

The route → filter step is deployment-supplied (``filter_factory``): a
bundle's runtime needs trust-root config and a wallet lookup, which are not in
the bundle's own artifacts (those describe the policy, not the deployment). A
factory that returns ``None`` for a selected route fails closed — a
named-but-unavailable route refuses the server.

- **Audit.** Every admission, allowed or refused, leaves an
  :class:`AdmissionRecord`: the server, the descriptor built for it, the
  route selected and which layer decided, and the composed chain. The call
  path is deny-on-objection, and a control that silently loses its filter
  *permits*, so "did every server end up under the gate it was meant to?"
  has to be answerable from something other than the absence of denials.
  :func:`~extensible_mcp.server._admit_servers` logs the records at boot.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .selection import LayeredBundleSelector, SelectionResult, provenance_descriptor
from .types import CallFilterResult, CallRequest
from .wasm_filter import WasmPolicyFilter

# route id -> a configured policy filter (or None if unavailable).
FilterFactory = Callable[[str], "WasmPolicyFilter | None"]


def describe_chain(policy_filter: Any) -> str:
    """The composed filter chain, outermost first, as one line.

    Walks the wrappers by their ``inner`` (or ``_inner``) attribute, the
    convention every shipped wrapper follows, naming each class; a filter
    carrying a ``route`` shows its name and tools; the leaf names its
    bundle. ``RouteScopedFilter[invoice: charge_invoice](InvoiceGatedFilter(
    family_spend_invoice))`` is what the demo's settlement server reads as.
    """
    name = type(policy_filter).__name__
    route = getattr(policy_filter, "route", None)
    if route is not None:
        tools = ", ".join(sorted(getattr(route, "tools", ())))
        name = f"{name}[{getattr(route, 'name', '?')}: {tools}]"
    inner = getattr(policy_filter, "inner", None)
    if inner is None:
        inner = getattr(policy_filter, "_inner", None)
    if inner is not None:
        return f"{name}({describe_chain(inner)})"
    bundle = getattr(policy_filter, "bundle", None)
    bundle_name = getattr(bundle, "name", None)
    return f"{name}({bundle_name})" if isinstance(bundle_name, str) else name


@dataclass(frozen=True)
class AdmissionRecord:
    """What one admission decided, kept for the boot-time audit."""

    server_name: str
    how_loaded: str
    descriptor: dict[str, Any]
    decision: SelectionResult
    chain: str | None  # the composed filter, or None when refused

    @property
    def admitted(self) -> bool:
        return self.chain is not None

    def summary(self) -> str:
        if self.admitted:
            return (
                f"{self.server_name!r} ({self.how_loaded}) -> route "
                f"{self.decision.route!r} via {self.decision.source}: {self.chain}"
            )
        return (
            f"{self.server_name!r} ({self.how_loaded}) REFUSED via "
            f"{self.decision.source}: {self.decision.reason}"
        )


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
        self._admissions: dict[str, AdmissionRecord] = {}

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
            assert result.route is not None
            policy_filter = self._filter_factory(result.route)
            if policy_filter is None:
                # Selected a route the deployment cannot provide → fail closed.
                result = SelectionResult(
                    None, result.source, f"route {result.route!r} unavailable"
                )
            else:
                self._filters[server_name] = policy_filter

        self._decisions[server_name] = result
        self._admissions[server_name] = AdmissionRecord(
            server_name=server_name,
            how_loaded=how_loaded,
            descriptor=descriptor,
            decision=result,
            chain=describe_chain(self._filters[server_name]) if result.allowed else None,
        )
        return result

    def admissions(self) -> list[AdmissionRecord]:
        """Every admission so far, in the order they were decided."""
        return list(self._admissions.values())

    def governs(self, server_name: str) -> bool:
        return server_name in self._filters

    def bundle_for(self, server_name: str, tool_name: str | None = None):
        """The policy bundle governing a server's tools, or ``None``. Lets the
        search-side augmenter surface the same bundle the call path enforces.

        With ``tool_name``, the answer is per tool: a filter that scopes
        itself to some of the server's tools (``governs_tool``, as a policy
        set's :class:`~extensible_mcp.policyset.RouteScopedFilter` does)
        governs the others not at all, so they are surfaced with no
        credential parameters -- the same split the call path applies."""
        policy_filter = self._filters.get(server_name)
        if policy_filter is None:
            return None
        governs_tool = getattr(policy_filter, "governs_tool", None)
        if tool_name is not None and governs_tool is not None and not governs_tool(tool_name):
            return None
        return policy_filter.bundle

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

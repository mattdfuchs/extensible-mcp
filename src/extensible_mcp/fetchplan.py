# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Assemble a policy's closed input by walking a fetch plan the bundle supplies.

A bundle's policy is *closed*: it reads a fixed set of top-level input fields,
and the companion ``fetchplan.json`` says where each one comes from — its
source ``kind`` plus, for ``wallet`` lookups, a subject drawn from an
earlier-assembled field. This module walks that plan in order and dispatches
each entry to a registered resolver. It never interprets the policy; the
resolvers are the only deployment-specific part.

The plan format, ``$input`` parameter substitution, in-order processing, and
fail-closed semantics mirror the executor a policy-authoring toolchain would
use to test its own bundles offline; this module's one deliberate departure
is that resolvers here are **async** (a wallet/DID lookup is network I/O), and
the deployment supplies real resolvers rather than test mocks.

Fail-closed: a resolver that cannot produce a required value raises
``FetchError``; the caller treats an un-assembled input as a denial rather than
guessing.

Source-kind → field, for the family-spend example:

- ``call``   — the LLM supplied it on the tool call (action content, signed VCs)
- ``config`` — a deployment constant (trust root)
- ``clock``  — the current time
- ``wallet`` — an attestation the proxy fetches by subject DID (membership)
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

logger = logging.getLogger("extensible_mcp.fetchplan")

# An async lookup of an attestation (e.g. a membership VC) by subject DID.
WalletLookup = Callable[[str], Awaitable[Any]]


class FetchError(Exception):
    """A required input field could not be resolved; the call fails closed."""


@dataclass
class FetchContext:
    """The deployment-supplied inputs the resolvers draw from.

    - ``envelope``: the call-sourced fields (``call``) — what the LLM provided
      on the tool call: the action, its arguments, and any signed VC bundles.
    - ``config``: deployment constants (``config``) — e.g. the trust root.
    - ``now``: current time in epoch seconds (``clock``).
    - ``wallet``: async lookup ``subject DID -> attestation`` (``wallet``). A
      deployment swaps in a DID-web / wallet client behind this one callable.
    """

    envelope: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    now: int = 0
    wallet: WalletLookup | None = None


class Resolver(Protocol):
    async def resolve(
        self,
        name: str,
        params: dict[str, Any],
        assembled: dict[str, Any],
        ctx: FetchContext,
    ) -> Any: ...


class CallResolver:
    """``call``: a field the LLM supplied on the tool call."""

    async def resolve(self, name, params, assembled, ctx):
        if name not in ctx.envelope:
            raise FetchError(f"tool call has no field {name!r}")
        return ctx.envelope[name]


class ConfigResolver:
    """``config``: a deployment constant."""

    async def resolve(self, name, params, assembled, ctx):
        if name not in ctx.config:
            raise FetchError(f"no deployment config for {name!r}")
        return ctx.config[name]


class ClockResolver:
    """``clock``: the current time."""

    async def resolve(self, name, params, assembled, ctx):
        return ctx.now


class WalletResolver:
    """``wallet``: an attestation fetched by subject DID.

    The subject comes from a ``$input`` parameter (e.g. ``requestVC.claims.iss``),
    already substituted from an earlier-assembled field. A missing attestation
    fails closed — it is fetched authoritatively, so "no credential for this
    subject" is a denial, not an empty default.
    """

    async def resolve(self, name, params, assembled, ctx):
        subject = params.get("subject")
        if subject is None:
            raise FetchError(f"wallet source for {name!r} has no subject")
        if ctx.wallet is None:
            raise FetchError(f"no wallet lookup configured for {name!r}")
        result = await ctx.wallet(subject)
        if result is None:
            raise FetchError(f"no credential for subject {subject!r}")
        return result


def default_resolvers() -> dict[str, Resolver]:
    return {
        "call": CallResolver(),
        "config": ConfigResolver(),
        "clock": ClockResolver(),
        "wallet": WalletResolver(),
    }


class FetchExecutor:
    """Assemble the closed policy input by walking the fetch plan."""

    def __init__(self, resolvers: dict[str, Resolver] | None = None) -> None:
        self.resolvers = resolvers if resolvers is not None else default_resolvers()

    async def assemble(
        self, plan: dict[str, Any], ctx: FetchContext
    ) -> dict[str, Any]:
        """Process plan entries in order, dispatching by source kind and
        substituting ``$input`` params from already-assembled fields. Returns
        the closed input document.

        **Guard-aware.** A call field whose guard marks it not-``always``
        required (a conditional credential, e.g. an authorization VC needed only
        above a threshold) is *omitted* when absent, rather than failing closed —
        and any field whose ``$input`` params reference an omitted field is
        omitted too. The policy then sees those fields as undefined and denies
        the paths that need them, while paths that don't (the solo tier) still
        evaluate. An absent *required* field still fails closed.
        """
        assembled: dict[str, Any] = {}
        omitted: set[str] = set()
        for entry in plan["entries"]:
            name = entry["field"]
            source = entry["source"]
            kind = source["kind"]
            resolver = self.resolvers.get(kind)
            if resolver is None:
                raise FetchError(f"no resolver registered for source kind {kind!r}")

            guard = entry.get("guard")
            optional = guard is not None and not guard.get("always", True)

            # Params may navigate into an earlier field that was omitted (an
            # absent optional credential); then this field is not needed either.
            try:
                params = self._resolve_params(source.get("params", {}), assembled)
            except FetchError:
                logger.debug("fetchplan: omitting %r (depends on an omitted field)", name)
                omitted.add(name)
                continue

            try:
                assembled[name] = await resolver.resolve(name, params, assembled, ctx)
            except FetchError:
                if optional:
                    logger.debug("fetchplan: omitting absent optional field %r", name)
                    omitted.add(name)
                    continue
                raise
        return assembled

    def _resolve_params(
        self, params: dict[str, Any], assembled: dict[str, Any]
    ) -> dict[str, Any]:
        resolved: dict[str, Any] = {}
        for key, val in params.items():
            if isinstance(val, dict) and "$input" in val:
                resolved[key] = self._navigate(assembled, val["$input"])
            else:
                resolved[key] = val
        return resolved

    @staticmethod
    def _navigate(doc: Any, path: str) -> Any:
        cur = doc
        for step in path.split("."):
            if not isinstance(cur, dict) or step not in cur:
                raise FetchError(f"fetch param path {path!r} not yet assembled")
            cur = cur[step]
        return cur

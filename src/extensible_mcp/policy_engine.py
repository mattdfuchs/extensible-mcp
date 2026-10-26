# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The evaluation-engine contract a :class:`~extensible_mcp.bundle.PolicyBundle`
runs against — the cut line that makes the bundle format engine-plural.

Everything above this Protocol (``manifest.json``, ``fetchplan.json``,
``guidance.py``'s denial renderer) is already engine-agnostic; only the
compiled/interpreted policy artifact itself differs between suppliers.
:class:`~extensible_mcp.wasm_policy.OpaWasmPolicy` and
:class:`~extensible_mcp.cel_policy.CelPolicy` and
:class:`~extensible_mcp.cedar_policy.CedarPolicy` all implement this Protocol,
so :mod:`extensible_mcp.wasm_filter` never needs to know which one it holds.

One hook sits beside the Protocol rather than in it: :func:`inline_guidance`,
for engines whose policy file can carry the denial sentences itself.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class PolicyEngine(Protocol):
    """One loaded, ready-to-query policy artifact."""

    def entrypoints(self) -> list[str]:
        """The rule/check paths this artifact exposes (e.g. ``pkg/allow``)."""
        ...

    def query(self, input_obj: Any, entrypoint: str) -> Any:
        """Evaluate ``entrypoint`` against ``input_obj``.

        Returns OPA's result-set shape (``[{"result": ...}]`` when defined,
        ``[]`` when not) regardless of which engine produced it — the one
        wire contract :mod:`wasm_filter` depends on. Raises
        :class:`~extensible_mcp.wasm_policy.PolicyEvaluationError` for any
        engine/config fault (never a silent policy "deny")."""
        ...


def inline_guidance(engine: Any) -> dict[str, Any] | None:
    """The guidance an engine can synthesise from sentences written *in the
    policy file*, or ``None`` when it carries none or does not support them.

    A hand-written bundle may omit ``guidance.json`` and keep its denial text
    where someone writing rules is likely to put it: beside the rule. CEL
    takes ``{"expr": ..., "sentence": ...}`` as a check's value, Cedar takes
    a ``@sentence("...")`` annotation on an ``@id`` forbid, and Rego already
    has ``deny_reason``. An engine that supports the first two exposes an
    optional ``inline_guidance()`` method returning the ``tiers`` structure
    the renderer reads (``{"tiers": [{"tier", "checks": [{"id", "sentence",
    "remedy_class"}]}]}``); this helper is how the loader asks, so a
    third-party engine that implements only the Protocol above is not
    required to know the method exists.
    """
    method = getattr(engine, "inline_guidance", None)
    if method is None:
        return None
    return method()

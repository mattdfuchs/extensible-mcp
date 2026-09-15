# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The evaluation-engine contract a :class:`~extensible_mcp.bundle.PolicyBundle`
runs against — the cut line that makes the bundle format engine-plural.

Everything above this Protocol (``manifest.json``, ``fetchplan.json``,
``guidance.py``'s denial renderer) is already engine-agnostic; only the
compiled/interpreted policy artifact itself differs between suppliers.
:class:`~extensible_mcp.wasm_policy.OpaWasmPolicy` and
:class:`~extensible_mcp.cel_policy.CelPolicy` both implement this Protocol,
so :mod:`extensible_mcp.wasm_filter` never needs to know which one it holds.
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

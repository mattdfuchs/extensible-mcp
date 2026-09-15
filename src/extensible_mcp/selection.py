# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Stage-one bundle selection: which policy bundle governs a server's tools.

A server is admitted at a URL; selection turns a **proxy-constructed provenance
descriptor** into either a bundle name or a refusal. The descriptor is built
from facts the proxy controls (the admitted server name/URL, configured trust
tier) — never from tool-supplied metadata, which is the zero-trust invariant.

Two backends behind one interface, *layered* not swapped:

- a **literal map** — operator overrides keyed on the admitted URL;
- a **Rego classifier** — a supplied ``Descriptor → decision`` policy,
  evaluated on the same WASM engine as the call path (a ``decision`` string
  entrypoint, no crypto builtins).

Precedence on one descriptor: an explicit map entry wins (a bundle name, or
``banned`` which does *not* fall through); a map miss falls to the classifier
(``bundle | deny_all``); a miss with no classifier denies. Both terminals end
in a denial, so the chain is fail-closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .wasm_policy import OpaWasmPolicy

# Reserved tokens.
BANNED = "banned"  # literal-map value: refuse, do not fall through
DENY_ALL = "deny_all"  # classifier's fail-closed default decision


def provenance_descriptor(
    *,
    origin_server: str,
    url: str,
    config_trust_tier: str,
    how_loaded: str | None = None,
    transport: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build a descriptor from proxy-controlled admission facts.

    ``origin_server`` is the server the proxy admitted (not the tool's
    self-reported name); ``config_trust_tier`` is proxy config. Extra fields are
    carried for forward-compatibility — a classifier reads only what it needs.
    """
    d: dict[str, Any] = {
        "origin_server": origin_server,
        "url": url,
        "config_trust_tier": config_trust_tier,
    }
    if how_loaded is not None:
        d["how_loaded"] = how_loaded
    if transport is not None:
        d["transport"] = transport
    d.update(extra)
    return d


@dataclass
class SelectionResult:
    """The outcome of bundle selection.

    ``bundle`` is ``None`` when the server must not be loaded (banned/denied).
    ``source`` records which layer decided, for logging/debugging.
    """

    bundle: str | None
    source: str  # "map" | "classifier" | "default"
    reason: str = ""

    @property
    def allowed(self) -> bool:
        return self.bundle is not None


class RegoClassifier:
    """A supplied provenance classifier (a ``decision``-valued policy).

    Evaluated in-process on the WASM engine; the entrypoint returns a string
    bundle key (``deny_all`` for the fail-closed default).
    """

    def __init__(self, wasm_path: str | Path, *, deny_value: str = DENY_ALL) -> None:
        self.policy = OpaWasmPolicy(wasm_path)
        self.deny_value = deny_value
        self._entrypoint = self._find_decision_entrypoint()

    def _find_decision_entrypoint(self) -> str:
        for ep in self.policy.entrypoints():
            if ep.endswith("/decision"):
                return ep
        raise ValueError(
            f"classifier exposes no '/decision' entrypoint; have "
            f"{self.policy.entrypoints()}"
        )

    def decide(self, descriptor: dict[str, Any]) -> str:
        """Return the classified bundle key (or ``deny_value``)."""
        result = self.policy.query(descriptor, self._entrypoint)
        if result and "result" in result[0]:
            return result[0]["result"]
        # A total `decision` rule with a default is always defined; treat any
        # absence as the fail-closed default anyway.
        return self.deny_value


class LayeredBundleSelector:
    """Literal-map overrides layered over an optional Rego classifier."""

    def __init__(
        self,
        literal_map: dict[str, str] | None = None,
        classifier: RegoClassifier | None = None,
        *,
        map_key: str = "url",
        banned_value: str = BANNED,
        deny_value: str = DENY_ALL,
    ) -> None:
        self.literal_map = dict(literal_map or {})
        self.classifier = classifier
        self.map_key = map_key
        self.banned_value = banned_value
        self.deny_value = deny_value

    def select(self, descriptor: dict[str, Any]) -> SelectionResult:
        # 1/2: explicit operator override by admitted URL.
        key = descriptor.get(self.map_key)
        if key is not None and key in self.literal_map:
            value = self.literal_map[key]
            if value == self.banned_value:
                return SelectionResult(None, "map", f"{key!r} explicitly banned")
            return SelectionResult(value, "map", f"operator override for {key!r}")

        # 3: fall through to the derived classifier.
        if self.classifier is None:
            return SelectionResult(
                None, "default", "no map entry and no classifier; failing closed"
            )
        decision = self.classifier.decide(descriptor)
        if decision == self.deny_value:
            return SelectionResult(None, "classifier", "classifier denied")
        return SelectionResult(decision, "classifier", "classified")

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Policy sets: one declaration of which route governs which server.

A :class:`PolicySet` is a ``policyset.json`` with three blocks::

    {
      "selection": {
        "map_key": "origin_server",
        "map": { "payments": "payments-vc", "settlement": "invoice" },
        "classifier": "classifier.wasm"
      },
      "server_types": {
        "family_spend_prod":    { "path": "bundles/family_spend_prod" },
        "family_spend_invoice": { "path": "bundles/family_spend_invoice" }
      },
      "routes": {
        "payments-vc": { "server_type": "family_spend_prod",    "tools": ["spend"],          "adapter": "wallet_bundle" },
        "invoice":     { "server_type": "family_spend_invoice", "tools": ["charge_invoice"] }
      }
    }

A **route** is a server type, the tools it governs and a wire adapter. A
**server type** is a bundle and the filter chain that enforces it. The
declaration names the bundle's directory; the chain is not in the
declaration at all -- it attaches to the server type when the deployment
registers it (:class:`ServerType`), so a route cannot declare a composition,
let alone a wrong one. The chain varies by bundle, not by route: two routes
over one server type run the same chain and differ only in adapter.

Three blocks in one file, not one file each, because the selection map's
values are route ids and a route's ``server_type`` is a server type name:
split across files, nothing would check that they agree. Here
:meth:`PolicySet.load` checks every cross-reference, and :meth:`PolicySet.bind`
checks that every name the declaration uses -- server type, adapter -- is one
the deployment registered. A name that resolves to nothing fails at boot,
instead of arriving later as a filter factory returning ``None``.

**The tools a route governs are declared, per route.** This is load-bearing.
A certified policy binds what its evidence binds; a settlement policy over a
merchant-signed invoice and two passkey approvals binds the merchant and the
total, and it cannot bind the tool name, because there is no signed statement
of a tool anywhere in that flow. A second gated tool on the same server would
therefore accept a replayed approval. The declaration is what buys the
guarantee that there is no such tool: a route's filter runs on exactly the
tools the route lists, and a call to any other tool on that server passes
through with the bundle's credential fields stripped, so the downstream never
sees arguments its schema does not declare.

Which fields are credentials is **derived from the bundle's fetch plan**, not
declared per route -- the plan already records which fields are
``call``-sourced, and a declared list is one more thing that can drift from
the manifest.

The split between what is declared and what is supplied is the one this
project uses everywhere (``primitives``, the credential issuer, the credential
mode): the declaration names shapes by name, the deployment registers
implementations against those names. Trust roots, wallet lookups, origins
and HTTP clients stay in the deployment, as the chain's closure, because a
bundle's artifacts describe the policy, not the deployment.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .bundle import PolicyBundle
from .routing import BundleRouter
from .selection import BANNED, LayeredBundleSelector, RegoClassifier
from .types import CallFilterResult, CallRequest

_ENGINES = ("rego", "cel", "cedar")


class PolicySetError(ValueError):
    """The declaration is malformed, or a name in it resolves to nothing."""


# --------------------------------------------------------------------------- #
# The declaration
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Route:
    """One route: a server type, the tools it governs, a wire adapter name."""

    name: str
    server_type: str
    tools: frozenset[str]
    adapter: str | None = None

    def governs_tool(self, tool_name: str) -> bool:
        """Whether this route's filter runs on ``tool_name``.

        Tools are declared unqualified, since a route governs one admitted
        server; a qualified ``server__tool`` is split on the reserved
        separator before the lookup."""
        return _action(tool_name) in self.tools


@dataclass(frozen=True)
class ServerTypeDeclaration:
    """A server type as declared: a name and the bundle directory it loads."""

    name: str
    path: Path
    engine: Literal["rego", "cel", "cedar"] | None = None


@dataclass(frozen=True)
class SelectionDeclaration:
    map_key: str
    map: dict[str, str]
    classifier: Path | None = None


# A chain builder: the deployment's composition over a loaded bundle, for one
# route, with that route's adapter resolved (or ``None`` when the route names
# none). Returns the call filter that enforces the bundle on the route's tools.
ChainBuilder = Callable[[PolicyBundle, Route, Any], Any]


@dataclass(frozen=True)
class ServerType:
    """What the deployment registers against a declared server type name.

    ``chain`` builds the filter chain over the loaded bundle. ``builtins``,
    ``primitives`` and ``engine`` are passed to :meth:`PolicyBundle.load`:
    a bundle that verifies passkeys needs ``default_builtins(webauthn_rp_id=
    ...)``, a deployment fact the declaration cannot carry.
    """

    chain: ChainBuilder
    builtins: dict[str, Any] | None = None
    primitives: dict[str, Any] | None = None


def _action(tool_name: str) -> str:
    return tool_name.split("__", 1)[1] if "__" in tool_name else tool_name


def _expect_object(value: Any, what: str, path: Path) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicySetError(f"{path}: {what} must be an object")
    return value


def _refuse_unknown_keys(obj: dict[str, Any], allowed: tuple[str, ...], what: str, path: Path) -> None:
    unknown = sorted(set(obj) - set(allowed))
    if unknown:
        raise PolicySetError(
            f"{path}: {what} has unexpected field(s) {unknown}; "
            f"allowed: {sorted(allowed)}"
        )


def _resolve(value: str, base: Path) -> Path:
    p = Path(value)
    return p if p.is_absolute() else base / p


@dataclass
class PolicySet:
    """A loaded, cross-checked declaration. :meth:`bind` turns it into a
    :class:`~extensible_mcp.routing.BundleRouter`."""

    path: Path
    selection: SelectionDeclaration
    server_types: dict[str, ServerTypeDeclaration] = field(default_factory=dict)
    routes: dict[str, Route] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "PolicySet":
        """Parse ``path`` and check every reference inside it.

        Refused, as :class:`PolicySetError`: an unknown key anywhere (a typo
        would otherwise declare nothing, silently); a selection map value
        that names no declared route (``banned`` is the one reserved value);
        a route whose ``server_type`` is not declared; a route with no tools,
        a duplicated tool, or a qualified ``server__tool`` name; a server
        type whose ``path`` is not a directory; a classifier that is not a
        file. Relative paths resolve against the file's own directory.
        """
        path = Path(path)
        try:
            raw = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            raise PolicySetError(f"{path}: not valid JSON: {e}") from e
        raw = _expect_object(raw, "the policy set", path)
        _refuse_unknown_keys(raw, ("selection", "server_types", "routes"), "the policy set", path)
        base = path.parent

        selection = cls._load_selection(raw.get("selection"), base, path)
        server_types = cls._load_server_types(raw.get("server_types"), base, path)
        routes = cls._load_routes(raw.get("routes"), path)

        # Cross-references: the reason this is one file.
        for key, value in selection.map.items():
            if value != BANNED and value not in routes:
                raise PolicySetError(
                    f"{path}: selection.map[{key!r}] names route {value!r}, which "
                    f"'routes' does not declare (declared: {sorted(routes)}; "
                    f"{BANNED!r} is the only other value)"
                )
        for route in routes.values():
            if route.server_type not in server_types:
                raise PolicySetError(
                    f"{path}: route {route.name!r} names server type "
                    f"{route.server_type!r}, which 'server_types' does not declare "
                    f"(declared: {sorted(server_types)})"
                )
        return cls(path=path, selection=selection, server_types=server_types, routes=routes)

    @staticmethod
    def _load_selection(raw: Any, base: Path, path: Path) -> SelectionDeclaration:
        raw = _expect_object(raw, "'selection'", path)
        _refuse_unknown_keys(raw, ("map_key", "map", "classifier"), "'selection'", path)
        map_key = raw.get("map_key", "url")
        if not isinstance(map_key, str) or not map_key:
            raise PolicySetError(f"{path}: selection.map_key must be a non-empty string")
        literal = _expect_object(raw.get("map", {}), "selection.map", path)
        for k, v in literal.items():
            if not isinstance(v, str) or not v:
                raise PolicySetError(
                    f"{path}: selection.map[{k!r}] must be a route id (a string)"
                )
        classifier: Path | None = None
        if "classifier" in raw:
            if not isinstance(raw["classifier"], str) or not raw["classifier"]:
                raise PolicySetError(f"{path}: selection.classifier must be a path")
            classifier = _resolve(raw["classifier"], base)
            if not classifier.is_file():
                raise PolicySetError(
                    f"{path}: selection.classifier {str(classifier)!r} is not a file"
                )
        if not literal and classifier is None:
            raise PolicySetError(
                f"{path}: 'selection' declares neither a map nor a classifier, so "
                "it would place no server"
            )
        return SelectionDeclaration(map_key=map_key, map=dict(literal), classifier=classifier)

    @staticmethod
    def _load_server_types(raw: Any, base: Path, path: Path) -> dict[str, ServerTypeDeclaration]:
        raw = _expect_object(raw, "'server_types'", path)
        if not raw:
            raise PolicySetError(f"{path}: 'server_types' declares nothing")
        out: dict[str, ServerTypeDeclaration] = {}
        for name, entry in raw.items():
            entry = _expect_object(entry, f"server_types[{name!r}]", path)
            _refuse_unknown_keys(entry, ("path", "engine"), f"server_types[{name!r}]", path)
            if not isinstance(entry.get("path"), str) or not entry["path"]:
                raise PolicySetError(f"{path}: server_types[{name!r}] must have a 'path'")
            directory = _resolve(entry["path"], base)
            if not directory.is_dir():
                raise PolicySetError(
                    f"{path}: server_types[{name!r}].path {str(directory)!r} is not a "
                    "directory"
                )
            engine = entry.get("engine")
            if engine is not None and engine not in _ENGINES:
                raise PolicySetError(
                    f"{path}: server_types[{name!r}].engine must be one of {list(_ENGINES)}"
                )
            out[name] = ServerTypeDeclaration(name=name, path=directory, engine=engine)
        return out

    @staticmethod
    def _load_routes(raw: Any, path: Path) -> dict[str, Route]:
        raw = _expect_object(raw, "'routes'", path)
        if not raw:
            raise PolicySetError(f"{path}: 'routes' declares nothing")
        out: dict[str, Route] = {}
        for name, entry in raw.items():
            if name == BANNED:
                raise PolicySetError(
                    f"{path}: {BANNED!r} is reserved as a selection value and cannot "
                    "name a route"
                )
            entry = _expect_object(entry, f"routes[{name!r}]", path)
            _refuse_unknown_keys(
                entry, ("server_type", "tools", "adapter"), f"routes[{name!r}]", path
            )
            server_type = entry.get("server_type")
            if not isinstance(server_type, str) or not server_type:
                raise PolicySetError(f"{path}: routes[{name!r}] must name a 'server_type'")
            tools = entry.get("tools")
            if not isinstance(tools, list) or not tools:
                raise PolicySetError(
                    f"{path}: routes[{name!r}].tools must be a non-empty list of the "
                    "tool names this route governs"
                )
            for t in tools:
                if not isinstance(t, str) or not t:
                    raise PolicySetError(f"{path}: routes[{name!r}].tools must be strings")
                if "__" in t:
                    raise PolicySetError(
                        f"{path}: routes[{name!r}].tools: {t!r} is qualified; a route "
                        "governs one admitted server, so tools are named bare"
                    )
            if len(set(tools)) != len(tools):
                raise PolicySetError(f"{path}: routes[{name!r}].tools lists a tool twice")
            adapter = entry.get("adapter")
            if adapter is not None and (not isinstance(adapter, str) or not adapter):
                raise PolicySetError(f"{path}: routes[{name!r}].adapter must be a name")
            out[name] = Route(
                name=name, server_type=server_type, tools=frozenset(tools), adapter=adapter
            )
        return out

    # -- binding ------------------------------------------------------------ #

    def bind(
        self,
        *,
        server_types: Mapping[str, ServerType],
        adapters: Mapping[str, Any] | None = None,
        default_trust_tier: str = "prod",
    ) -> BundleRouter:
        """Resolve every name against the deployment's registrations, load
        every bundle, build every route's chain, and return the router.

        Everything is built here, before any server is admitted, so a bundle
        that does not load or a chain that cannot be composed is a boot
        failure with its own message. Refused: a declared server type with no
        registration, a registration for no declared server type, a route
        naming an adapter that is not registered, and an adapter registered
        for no route. Both directions, because the typo can be on either
        side and the one that goes unmentioned is the one that admits a
        server to nothing.
        """
        adapters = dict(adapters or {})
        declared, registered = set(self.server_types), set(server_types)
        if declared != registered:
            raise PolicySetError(
                f"{self.path}: server types declared and registered differ: "
                f"declared but not registered {sorted(declared - registered)}, "
                f"registered but not declared {sorted(registered - declared)}"
            )
        named = {r.adapter for r in self.routes.values() if r.adapter is not None}
        if named != set(adapters):
            raise PolicySetError(
                f"{self.path}: adapters named by routes and registered differ: "
                f"named but not registered {sorted(named - set(adapters))}, "
                f"registered but named by no route {sorted(set(adapters) - named)}"
            )

        bundles: dict[str, PolicyBundle] = {}
        for name, decl in self.server_types.items():
            reg = server_types[name]
            bundles[name] = PolicyBundle.load(
                decl.path,
                name=name,
                engine=decl.engine,
                builtins=reg.builtins,
                primitives=reg.primitives,
            )

        filters: dict[str, RouteScopedFilter] = {}
        for route in self.routes.values():
            bundle = bundles[route.server_type]
            adapter = adapters[route.adapter] if route.adapter is not None else None
            chain = server_types[route.server_type].chain(bundle, route, adapter)
            filters[route.name] = RouteScopedFilter(route, chain, bundle.credential_fields())

        classifier = (
            RegoClassifier(self.selection.classifier)
            if self.selection.classifier is not None
            else None
        )
        selector = LayeredBundleSelector(
            self.selection.map, classifier, map_key=self.selection.map_key
        )
        # A classifier may return a route id the declaration does not carry;
        # the router's existing refusal ("route unavailable") covers it.
        return BundleRouter(selector, filters.get, default_trust_tier=default_trust_tier)


# --------------------------------------------------------------------------- #
# Per-route tool scoping
# --------------------------------------------------------------------------- #


class RouteScopedFilter:
    """Run a route's chain on the tools the route governs; pass every other
    tool on the same server through, with the bundle's credential fields
    stripped.

    The strip is what keeps an informational tool from receiving a stray
    credential the downstream's schema never declared. The fields come from
    the bundle's own fetch plan (:meth:`PolicyBundle.credential_fields`), so
    they are exactly the ones the governed tools take, never a union across
    routes.
    """

    def __init__(self, route: Route, inner: Any, credential_fields: list[str]) -> None:
        self._route = route
        self._inner = inner
        self._credential_fields = frozenset(credential_fields)

    @property
    def route(self) -> Route:
        return self._route

    @property
    def bundle(self) -> PolicyBundle:
        # The augmenter reads ``bundle_for()`` -> ``filter.bundle``, through
        # whatever wrapper sits in between.
        return self._inner.bundle

    def governs_tool(self, tool_name: str) -> bool:
        return self._route.governs_tool(tool_name)

    async def check(self, request: CallRequest) -> CallFilterResult:
        if not self._route.governs_tool(request.tool_name):
            args = {
                k: v for k, v in request.arguments.items()
                if k not in self._credential_fields
            }
            return CallFilterResult(allowed=True, tool_name=request.tool_name, arguments=args)
        return await self._inner.check(request)

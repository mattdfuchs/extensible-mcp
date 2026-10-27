# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Policy bundles attached from ``config.json`` — no Python required.

``filters.policy_bundles`` maps a server name to a bundle directory and the
facts its fetch plan reads from ``config``. This module turns each entry
into the same two things an embedder wires by hand: a call filter that
enforces the bundle on that server's tools, and a search-side augmenter so
the LLM sees the credential parameters the bundle requires.

What it deliberately does not do:

- **Resolve a** ``wallet`` **source.** A wallet lookup is code — it fetches a
  credential from somewhere the deployment knows about — and no config key
  can stand in for it. A bundle whose plan has one is refused at startup
  with a message saying where it is attached instead, rather than loaded
  with a source that would fail on every call.
- **Select** a bundle per server. That is ``bundle_router``'s job, decided
  at admission from provenance facts; this is the direct, declared mapping.
- **Choose** a non-default host-builtin or primitive registry. A bundle
  that verifies passkeys needs ``default_builtins(webauthn_rp_id=...)``,
  which is a deployment fact an embedder supplies.

Everything is built eagerly in :func:`build_declared_bundle_filters`, which
``create_server`` calls before the lifespan exists, so a bundle that cannot
be loaded is a startup failure with the engine's own message — never a
running proxy with a gate silently missing.
"""

from __future__ import annotations

from typing import Any

from .augment import BundleAugmenter
from .bundle import PolicyBundle
from .config import Config, PolicyBundleConfig
from .replay import SingleUseEvidenceFilter, wallet_bundle_jti
from .types import CallFilterResult, CallRequest
from .wasm_filter import WasmPolicyFilter

# The fetch-plan source kinds a declared bundle may use. ``wallet`` is the
# one that needs code.
_CONFIGURABLE_SOURCES = frozenset({"call", "config", "clock", "derive"})


class ServerScopedFilter:
    """Apply a bundle's filter to one server's tools; every other server's
    calls pass through untouched.

    Scoping by server rather than by action set is what the declared form
    means: ``policy_bundles`` is keyed by server name, so the whole server is
    governed, the way ``bundle_router`` governs the server it admits. A
    deployment that wants to gate some of a server's tools and not others
    is choosing a per-tool policy, which belongs in the rules, not here.
    """

    def __init__(self, server_name: str, inner: Any) -> None:
        self._server_name = server_name
        self._inner = inner

    @property
    def server_name(self) -> str:
        return self._server_name

    @property
    def bundle(self) -> PolicyBundle:
        # The augmenter reads ``bundle_for()`` -> ``filter.bundle``, through
        # whatever wrapper (single-use) sits in between.
        return self._inner.bundle

    async def check(self, request: CallRequest) -> CallFilterResult:
        if request.server_name != self._server_name:
            return CallFilterResult(
                allowed=True, tool_name=request.tool_name, arguments=request.arguments
            )
        return await self._inner.check(request)


class DeclaredBundles:
    """The server -> bundle map the search-side augmenter reads.

    ``BundleAugmenter`` takes anything with ``bundle_for(server_name)``; the
    admission-time router provides it for selected bundles, this provides it
    for declared ones. Same contract, so the augmenter is shared unchanged.
    """

    def __init__(self, filters: dict[str, ServerScopedFilter]) -> None:
        self._filters = dict(filters)

    def bundle_for(self, server_name: str) -> PolicyBundle | None:
        f = self._filters.get(server_name)
        return f.bundle if f is not None else None

    def governs(self, server_name: str) -> bool:
        return server_name in self._filters


def credential_jti(value: Any) -> str | None:
    """The ``jti`` of a credential in either wire shape the proxy knows.

    The hand-written teaching bundles take ``{jws, claims}`` — the claims
    travel beside the signature and the policy binds them to it — so the
    ``jti`` is read from ``claims``. A wallet ``{token, membership}`` bundle
    carries it inside the token; that is deferred to the existing extractor.
    Anything else is not a credential this filter can spend, and ``None``
    lets the policy filter refuse it on its own terms.
    """
    if isinstance(value, dict) and isinstance(value.get("claims"), dict):
        jti = value["claims"].get("jti")
        return jti if isinstance(jti, str) and jti else None
    return wallet_bundle_jti(value)


def _refuse_wallet_sources(bundle: PolicyBundle, entry: PolicyBundleConfig) -> None:
    wallet_fields = [
        e["field"]
        for e in bundle.fetchplan.get("entries", [])
        if e.get("source", {}).get("kind") not in _CONFIGURABLE_SOURCES
    ]
    if wallet_fields:
        raise ValueError(
            f"Policy bundle for '{entry.server}' ({entry.path}) fetches "
            f"{wallet_fields} from a 'wallet' source, which needs a lookup "
            "supplied in code: a wallet lookup is a function the deployment "
            "writes, not a config value. Attach this bundle from an entry "
            "point instead — build a WasmPolicyFilter(bundle, config=..., "
            "wallet_lookup=...) and pass it to create_server(..., "
            "extra_call_filters=[...])."
        )


def _refuse_unknown_single_use(bundle: PolicyBundle, entry: PolicyBundleConfig) -> None:
    credential_fields = set(bundle.credential_fields())
    unknown = sorted(set(entry.single_use) - credential_fields)
    if unknown:
        raise ValueError(
            f"Policy bundle for '{entry.server}': 'single_use' names {unknown}, "
            f"which the bundle does not take as a credential field "
            f"(it takes {sorted(credential_fields) or 'none'}). Spending a field "
            "the policy never reads would spend nothing."
        )


def build_declared_bundle_filters(
    config: Config,
) -> tuple[list[ServerScopedFilter], list[BundleAugmenter]]:
    """Load every ``filters.policy_bundles`` entry into a scoped call filter,
    and one augmenter over all of them for the search side.

    Raises on the first bundle that cannot be loaded or that this form
    cannot serve, with the engine's or this module's own message. The
    caller treats that as a startup failure.
    """
    scoped: dict[str, ServerScopedFilter] = {}
    for server, entry in config.filters.policy_bundles.items():
        bundle = PolicyBundle.load(entry.path, name=server, engine=entry.engine)
        _refuse_wallet_sources(bundle, entry)
        _refuse_unknown_single_use(bundle, entry)
        inner: Any = WasmPolicyFilter(bundle, config=entry.config)
        if entry.single_use:
            inner = SingleUseEvidenceFilter(
                inner,
                credential_fields=tuple(entry.single_use),
                extract_id=credential_jti,
            )
        scoped[server] = ServerScopedFilter(server, inner)
    if not scoped:
        return [], []
    augmenter = BundleAugmenter(DeclaredBundles(scoped))  # type: ignore[arg-type]
    return list(scoped.values()), [augmenter]

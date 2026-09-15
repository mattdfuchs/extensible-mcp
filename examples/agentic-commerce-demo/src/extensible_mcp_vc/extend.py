# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Wrapper around ``extensible_mcp.create_server`` that wires the VC pieces in."""

from __future__ import annotations

from collections.abc import Sequence

import httpx
from extensible_mcp import CallFilter, ResponseFilter, ServerLoadFilter, ToolFilter
from extensible_mcp.config import Config
from extensible_mcp.server import create_server
from fastmcp import FastMCP

from .config import VCConfig
from .did_resolver import DidWebResolver
from .meta_tools import build_vc_tools, register_vc_callback_route
from .schema_augmenter import VCSchemaAugmenter
from .shadow import ShadowCallFilter, jsonl_sink
from .vc_filter import VCCallFilter


def _build_shadow_policy_filter(vc_config: VCConfig):
    """The supplied-bundle VCPolicyFilter the harness observes: the bundle at
    ``shadow_bundle_dir``, the fork's on-the-wire credential names mapped
    onto the policy's input fields, and the same trusted-admin set as the
    primary (documents from config pre-seeded, unknowns fetched live)."""
    from extensible_mcp import (
        PolicyBundle,
        VCPolicyFilter,
        WalletBundleAdapter,
        ed25519_jwk_from_document,
    )
    from extensible_mcp.didweb import DidWebResolver as PolicyKeyResolver

    preresolved = {}
    for did, doc in vc_config.preresolved_did_documents.items():
        jwk = ed25519_jwk_from_document(doc)
        if jwk is not None:
            preresolved[did] = jwk

    async def fetch(url: str) -> dict:
        async with httpx.AsyncClient(
            timeout=vc_config.wallet_timeout_seconds
        ) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()

    return VCPolicyFilter(
        PolicyBundle.load(vc_config.shadow_bundle_dir),
        adapter=WalletBundleAdapter(
            request_field="vc_request", authorization_field="vc_authorization"
        ),
        resolver=PolicyKeyResolver(
            vc_config.trusted_admin_dids,
            fetcher=fetch,
            cache_ttl_seconds=vc_config.did_web_cache_ttl_seconds,
            preresolved=preresolved,
        ),
        trusted_admin_dids=vc_config.trusted_admin_dids,
    )


def extend_server(
    config: Config,
    vc_config: VCConfig,
    *,
    resolver: DidWebResolver | None = None,
    extra_search_filters: Sequence[ToolFilter] = (),
    extra_call_filters: Sequence[CallFilter] = (),
    extra_response_filters: Sequence[ResponseFilter] = (),
    extra_load_filters: Sequence[ServerLoadFilter] = (),
) -> FastMCP:
    """Build a FastMCP proxy with VC schema augmentation, the VC CallFilter,
    and the two VC meta-tools all wired in.

    When ``vc_config.shadow_bundle_dir`` is set, the call filter is wrapped
    in the migration :class:`ShadowCallFilter`: ``VCCallFilter`` still gates
    every call, and the supplied-bundle ``VCPolicyFilter`` is evaluated
    alongside — recorded, and (with ``shadow_log_file``) appended to a JSONL
    divergence log. The harness is exposed as ``server.shadow_harness`` for
    ``summary()`` review; ``None`` when shadow mode is off.
    """
    augmenter = VCSchemaAugmenter(
        vc_config.gated_tools,
        optional_authorization_tools=vc_config.optional_authorization_tools,
    )
    vc_filter = VCCallFilter(vc_config, resolver=resolver)

    call_filter: CallFilter = vc_filter
    harness: ShadowCallFilter | None = None
    if vc_config.shadow_bundle_dir:
        sink = (
            jsonl_sink(vc_config.shadow_log_file)
            if vc_config.shadow_log_file
            else None
        )
        harness = ShadowCallFilter(
            vc_filter, _build_shadow_policy_filter(vc_config), sink=sink
        )
        call_filter = harness

    originator_client = httpx.AsyncClient(
        base_url=vc_config.originator_wallet_url,
        timeout=vc_config.wallet_timeout_seconds,
    )
    approver_client = httpx.AsyncClient(
        base_url=vc_config.approver_wallet_url,
        timeout=vc_config.wallet_timeout_seconds,
    )
    # The callback route needs a live server to register on, but the tools
    # it shares a `pending` store with need to exist *before* create_server
    # (which owns building the FastMCP object) — so `pending` is built here,
    # first, and threaded to both halves.
    pending: dict = {}
    vc_tools = build_vc_tools(
        originator_client=originator_client,
        approver_client=approver_client,
        pending=pending,
        callback_base_url=vc_config.callback_base_url,
        callback_timeout_seconds=vc_config.callback_timeout_seconds,
    )

    server = create_server(
        config,
        extra_search_filters=(augmenter, *extra_search_filters),
        extra_call_filters=(call_filter, *extra_call_filters),
        extra_response_filters=extra_response_filters,
        extra_load_filters=extra_load_filters,
        local_tools=vc_tools,
    )
    server.shadow_harness = harness
    register_vc_callback_route(server, vc_config.callback_base_url, pending)
    return server

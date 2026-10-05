# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""MCP proxy that replaces tool definitions with semantic search."""

from .augment import BundleAugmenter
from .bundle import PolicyBundle
from .didweb import (
    DidResolutionError,
    DidWebResolver,
    did_web_to_url,
    ed25519_jwk_from_document,
)
from .fetchplan import FetchContext, FetchError, FetchExecutor, WalletLookup
from .filters import CallFilter, ResponseFilter, ServerLoadFilter, ToolFilter
from .guidance import render_denial
from .replay import (
    InMemorySpentStore,
    SingleUseEvidenceFilter,
    SpentStore,
    wallet_bundle_jti,
)
from .issuer import IssuerRegistry
from .routing import BundleRouter
from .selection import (
    LayeredBundleSelector,
    RegoClassifier,
    SelectionResult,
    provenance_descriptor,
)
from .types import (
    CallFilterResult,
    CallRequest,
    CallResponse,
    LocalTool,
    ResponseFilterResult,
    SearchResult,
    ServerLoadRequest,
    ServerLoadResult,
    ToolRecord,
)
from .wallet_bundle import AdaptedCall, WalletBundleAdapter, WalletBundleError, make_membership_lookup
from .wasm_filter import VCPolicyFilter, WasmPolicyFilter, policy_deny_reason
from .wasm_policy import (
    HostBuiltinError,
    OpaWasmPolicy,
    PolicyEvaluationError,
    default_builtins,
)

__all__ = [
    "BundleAugmenter",
    "BundleRouter",
    "CallFilter",
    "CallFilterResult",
    "CallRequest",
    "CallResponse",
    "DidResolutionError",
    "DidWebResolver",
    "FetchContext",
    "FetchError",
    "FetchExecutor",
    "HostBuiltinError",
    "IssuerRegistry",
    "LayeredBundleSelector",
    "LocalTool",
    "OpaWasmPolicy",
    "PolicyBundle",
    "PolicyEvaluationError",
    "RegoClassifier",
    "ResponseFilter",
    "ResponseFilterResult",
    "SearchResult",
    "SelectionResult",
    "ServerLoadFilter",
    "ServerLoadRequest",
    "ServerLoadResult",
    "ToolFilter",
    "ToolRecord",
    "AdaptedCall",
    "VCPolicyFilter",
    "WalletBundleAdapter",
    "WalletBundleError",
    "WalletLookup",
    "WasmPolicyFilter",
    "default_builtins",
    "did_web_to_url",
    "ed25519_jwk_from_document",
    "make_membership_lookup",
    "policy_deny_reason",
    "provenance_descriptor",
    "render_denial",
    "InMemorySpentStore",
    "SingleUseEvidenceFilter",
    "SpentStore",
    "wallet_bundle_jti",
]

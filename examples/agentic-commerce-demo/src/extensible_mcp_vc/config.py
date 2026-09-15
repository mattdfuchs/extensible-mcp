# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Configuration for VC gating."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class VCConfig:
    """Configuration for verifiable-credential gating in extensible-mcp.

    ``gated_tools`` accepts fnmatch patterns matched against the qualified
    tool name (``payments__*``, ``github__close_issue``, ...).

    ``trusted_admin_dids`` is the closed set of did:web identifiers whose
    membership VCs are honored. Any membership signed by an issuer outside
    this set is rejected.

    ``preresolved_did_documents`` lets tests (and static deployments) skip
    the HTTPS resolution step by supplying the DID document directly.

    ``callback_base_url`` enables asynchronous wallet approvals. When set,
    the proxy sends each ``/sign/{request,authorization}`` POST with a
    ``callback_url`` pointing at ``{callback_base_url}/vc-callback/{id}``,
    receives 202 from the wallet, and waits for the wallet to push the
    signed bundle back when the human approves. This lets a parent who's
    not at the terminal still drive the chain without holding open an
    HTTP connection. When empty, wallets stay in synchronous mode and
    block on stdin (backwards-compatible with the v0.1 demo).

    ``callback_timeout_seconds`` is how long the proxy will await the
    callback before giving up and returning an error to the LLM. Default
    150s sits comfortably under n8n's per-tool 180s HTTP timeout.
    """

    originator_wallet_url: str
    approver_wallet_url: str
    trusted_admin_dids: list[str]
    gated_tools: list[str]
    wallet_timeout_seconds: float = 120.0
    did_web_cache_ttl_seconds: int = 3600
    preresolved_did_documents: dict[str, dict[str, Any]] = field(default_factory=dict)
    callback_base_url: str = ""
    callback_timeout_seconds: float = 150.0
    # Tools where vc_request is mandatory but vc_authorization is optional.
    # Tools where the approver's credential is conditional rather than
    # always required — e.g. "parental authorization only above $10". The
    # condition itself is a policy decision, expressed as a tier in the
    # bundle governing the tool. Patterns use ``fnmatch`` like
    # ``gated_tools``.
    optional_authorization_tools: list[str] = field(default_factory=list)

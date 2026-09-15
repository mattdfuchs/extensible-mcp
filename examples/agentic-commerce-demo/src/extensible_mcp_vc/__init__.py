# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Signed-evidence meta-tools and wire adapters for extensible-mcp.

Enforcement itself lives in ``extensible_mcp``'s policy-bundle engine: a
bundle decides, and the pieces here supply the evidence it decides over --
tools the LLM calls to obtain a wallet-signed credential or a passkey
approval, the canonical invoice form a merchant signs, and the settlement
and fulfillment legs. See ``examples/boot_demo.py`` for the smallest
end-to-end run and ``examples/family_proxy_server.py`` for the full one.
"""

from .config import VCConfig
from .did_resolver import DidResolutionError, DidWebResolver, did_web_url

__all__ = [
    "DidResolutionError",
    "DidWebResolver",
    "VCConfig",
    "did_web_url",
]

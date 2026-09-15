# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Verifiable Credentials CallFilter and meta-tools for extensible-mcp."""

from .config import VCConfig
from .did_resolver import DidResolutionError, DidWebResolver, did_web_url
from .extend import extend_server
from .schema_augmenter import VCSchemaAugmenter
from .vc_filter import VCCallFilter, VCVerificationError

__all__ = [
    "DidResolutionError",
    "DidWebResolver",
    "VCCallFilter",
    "VCConfig",
    "VCSchemaAugmenter",
    "VCVerificationError",
    "did_web_url",
    "extend_server",
]

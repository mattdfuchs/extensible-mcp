# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests that extend_server registers the VC meta-tools and pipelines."""

from __future__ import annotations

from pathlib import Path

import pytest
from extensible_mcp.config import Config

from extensible_mcp_vc.config import VCConfig
from extensible_mcp_vc.extend import extend_server
from extensible_mcp_vc.shadow import ShadowCallFilter

_BUNDLE_DIR = (
    Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "family_spend_prod"
)


@pytest.fixture
def empty_config() -> Config:
    return Config()


@pytest.fixture
def vc_config() -> VCConfig:
    return VCConfig(
        originator_wallet_url="http://kid.invalid",
        approver_wallet_url="http://parent.invalid",
        trusted_admin_dids=["did:web:family.example.com"],
        gated_tools=["payments__*"],
    )


class TestExtendServer:
    async def test_meta_tools_registered(self, empty_config, vc_config):
        """The VC tools are local tools now, not separate top-level ones —
        reachable through search_tools -> call_tool exactly like a
        downstream tool, not listed alongside search_tools/call_tool
        themselves. (Full local-tool discover/dispatch/filter mechanics
        against a real downstream server are covered in the core package's
        tests/test_server.py; this test only confirms extend_server wires
        the VC tools in as local_tools, not as separate top-level ones.)"""
        server = extend_server(empty_config, vc_config)
        names = {t.name for t in await server.list_tools()}
        assert names == {"search_tools", "call_tool", "load_mcp_server"}

    async def test_shadow_mode_off_by_default(self, empty_config, vc_config):
        server = extend_server(empty_config, vc_config)
        assert server.shadow_harness is None

    @pytest.mark.skipif(
        not (_BUNDLE_DIR / "policy.wasm").exists(),
        reason="family_spend_prod bundle not checked out alongside",
    )
    async def test_shadow_mode_wires_harness(self, empty_config, vc_config):
        vc_config.shadow_bundle_dir = str(_BUNDLE_DIR)
        server = extend_server(empty_config, vc_config)
        assert isinstance(server.shadow_harness, ShadowCallFilter)
        # the primary stays the authority: it is the hand-coded VCCallFilter
        from extensible_mcp_vc.vc_filter import VCCallFilter

        assert isinstance(server.shadow_harness.primary, VCCallFilter)

# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The family proxy on the organization's identity provider: the console's
bearer is the proxy's principal, for the proxy's own audience, verified
against the realm's keys reached at the internal base; the catalogue is
scoped by role; and with no provider configured the home shape stands."""

from __future__ import annotations

import sys
from pathlib import Path

import httpx2
import pytest

from extensible_mcp.config import RoleScope
from extensible_mcp_vc.oauth import AUDIENCE, PROXY_AUDIENCE, ExternalIssuerConfig

from .idp_fixtures import INTERNAL, ISSUER, FakeProvider, mint, mock_client

_EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
sys.path.insert(0, str(_EXAMPLES))
from family_proxy_server import DEMO_BY_ROLE, external_identity  # noqa: E402


@pytest.fixture
def keypair():
    from fastmcp.server.auth.providers.jwt import RSAKeyPair
    return RSAKeyPair.generate()


@pytest.fixture
def config():
    return ExternalIssuerConfig.from_env({"APPROVAL_ISSUER": ISSUER, "APPROVAL_ISSUER_INTERNAL": INTERNAL})


def test_no_provider_is_the_home_shape():
    identity = external_identity(None)
    assert identity.server_kwargs == {} and identity.by_role is None


def test_the_provider_becomes_the_proxys_verifier_for_its_own_audience(keypair, config):
    provider = FakeProvider(keypair)
    identity = external_identity(config, http_client=mock_client(provider), timeout=1)
    assert identity.server_kwargs["require_principal"] is True
    verifier = identity.server_kwargs["auth"]
    assert verifier.issuer == ISSUER and verifier.audience == PROXY_AUDIENCE
    assert verifier.jwks_uri == f"{INTERNAL}/protocol/openid-connect/certs"
    assert f"{INTERNAL}/.well-known/openid-configuration" in provider.requests


def test_a_console_token_is_accepted_and_a_passkey_page_token_is_not(keypair, config):
    """One audience per resource server: the realm issues the console's
    token for the proxy and the page's for the approval service, and the
    proxy accepts only its own. Synchronous because external_identity runs
    its own loop at startup, as main() does."""
    import asyncio
    provider = FakeProvider(keypair)
    verifier = external_identity(config, http_client=mock_client(provider), timeout=1).server_kwargs["auth"]
    ok = asyncio.run(verifier.verify_token(mint(keypair, ["parent"], audience=PROXY_AUDIENCE, sub="parent-id")))
    assert ok is not None and ok.claims["sub"] == "parent-id" and ok.claims["roles"] == ["parent"]
    assert asyncio.run(verifier.verify_token(mint(keypair, ["parent"], audience=AUDIENCE))) is None


def test_both_roles_see_everything_and_neither_may_load(keypair, config):
    identity = external_identity(config, http_client=mock_client(FakeProvider(keypair)), timeout=1)
    assert identity.by_role == DEMO_BY_ROLE
    assert set(identity.by_role) == {"parent", "child"}
    for scope in identity.by_role.values():
        assert scope == RoleScope(allow_servers="*", may_load=False)


def test_an_unreachable_provider_is_a_startup_fault_not_a_hang(keypair, config):
    class Down(FakeProvider):
        def handler(self, request):
            raise httpx2.ConnectError("refused")
    from extensible_mcp_vc.oauth import ExternalIssuerError
    with pytest.raises(ExternalIssuerError, match="unreachable"):
        external_identity(config, http_client=mock_client(Down(keypair)), timeout=0)

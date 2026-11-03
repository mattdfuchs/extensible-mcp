# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Inbound identity: a verified token becomes a Principal, and every pipeline
sees it.

The verifier is FastMCP's. What is tested here is ours: the claims-to-
principal mapping with the identity case and the total map, the two config
blocks, and -- over real Streamable HTTP with a static verifier -- that the
token on the request reaches the filters as a Principal and that a request
with no token never reaches them at all.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from fastmcp.utilities.tests import run_server_async

from extensible_mcp.config import AccessControlConfig, Config, FiltersConfig, load_config
from extensible_mcp.principal import PrincipalError, PrincipalMapping, principal_from_claims
from extensible_mcp.server import create_server
from extensible_mcp.types import (
    CallFilterResult,
    CallRequest,
    CallResponse,
    Principal,
    ResponseFilterResult,
    ServerConfig,
    ServerLoadRequest,
    ServerLoadResult,
)

MOCK_SERVER = str(Path(__file__).parent / "mock_server.py")
ISSUER = "https://idp.example/realms/household"


# --------------------------------------------------------------------------- #
# Claims -> Principal
# --------------------------------------------------------------------------- #


def _claims(**extra: Any) -> dict[str, Any]:
    return {"sub": "user-1", "iss": ISSUER, **extra}


def test_the_identity_case_reads_roles_verbatim():
    p = principal_from_claims(_claims(roles=["parent", "child"], client_id="console"))
    assert p == Principal(
        sub="user-1", iss=ISSUER, roles=frozenset({"parent", "child"}), client_id="console"
    )


def test_a_dotted_claim_path_reaches_a_stock_realm_role_set():
    mapping = PrincipalMapping(roles_claim="realm_access.roles")
    p = principal_from_claims(_claims(realm_access={"roles": ["parent"]}), mapping)
    assert p.roles == frozenset({"parent"})


def test_a_single_string_role_claim_reads_as_one_role():
    """The demo's own tokens carry ``role: "parent"``."""
    assert principal_from_claims(_claims(role="parent")).roles == frozenset({"parent"})
    assert principal_from_claims(_claims(roles="child")).roles == frozenset({"child"})


def test_a_role_map_is_total(caplog):
    """A value the map does not name is dropped and logged once, never
    passed through under its foreign name."""
    mapping = PrincipalMapping(role_map={"household-parent": "parent"})
    with caplog.at_level(logging.WARNING, logger="extensible_mcp.principal"):
        first = principal_from_claims(_claims(roles=["household-parent", "admin-of-everything"]), mapping)
        second = principal_from_claims(_claims(roles=["admin-of-everything"]), mapping)
    assert first.roles == frozenset({"parent"})
    assert second.roles == frozenset()
    dropped = [r for r in caplog.records if "admin-of-everything" in r.getMessage()]
    assert len(dropped) == 1


def test_the_authentication_claims_are_carried_and_typed():
    p = principal_from_claims(_claims(auth_time=1700000000, amr=["webauthn", "pwd"], acr="urn:high"))
    assert (p.auth_time, p.amr, p.acr) == (1700000000, ("webauthn", "pwd"), "urn:high")
    bare = principal_from_claims(_claims(auth_time="soon", amr="webauthn"))
    assert (bare.auth_time, bare.amr, bare.acr) == (None, None, None)


def test_azp_names_the_agent_when_the_verifier_did_not():
    assert principal_from_claims(_claims(azp="claude-desktop")).client_id == "claude-desktop"
    assert principal_from_claims(_claims(azp="x"), client_id="verifier-said").client_id == "verifier-said"


@pytest.mark.parametrize("missing", ["sub", "iss"])
def test_a_token_naming_nobody_is_refused_not_anonymous(missing):
    claims = _claims()
    del claims[missing]
    with pytest.raises(PrincipalError, match=f"'{missing}'"):
        principal_from_claims(claims)


def test_a_principal_is_frozen_and_never_the_token():
    p = principal_from_claims(_claims(roles=["parent"]))
    with pytest.raises(Exception):
        p.sub = "someone-else"  # type: ignore[misc]
    assert "token" not in {f for f in p.__dataclass_fields__}


# --------------------------------------------------------------------------- #
# The config blocks
# --------------------------------------------------------------------------- #


def _write(tmp_path: Path, **blocks: Any) -> Path:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"mcpServers": {"m": {"command": "x"}}, **blocks}))
    return path


def test_auth_block_builds_resource_server_mode(tmp_path):
    (tmp_path / "idp.pem").write_text("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n")
    config = load_config(_write(
        tmp_path,
        auth={"issuer": ISSUER, "audience": "extensible-mcp", "public_key_file": "idp.pem"},
        principal={"roles_claim": "realm_access.roles", "role_map": {"hp": "parent"}},
    ))
    assert config.auth is not None
    assert config.auth.issuer == ISSUER and config.auth.audience == "extensible-mcp"
    assert config.auth.public_key_file == tmp_path / "idp.pem" and config.auth.jwks_uri is None
    assert config.auth.algorithm == "RS256"
    assert config.principal.roles_claim == "realm_access.roles"
    assert config.principal.role_map == {"hp": "parent"}


def test_no_blocks_means_no_auth_and_verbatim_roles(tmp_path):
    config = load_config(_write(tmp_path))
    assert config.auth is None
    assert config.principal.roles_claim == "roles" and config.principal.role_map is None


@pytest.mark.parametrize(
    "auth, needle",
    [
        ({"issuer": ISSUER, "audience": "a"}, "exactly one of"),
        ({"issuer": ISSUER, "audience": "a", "jwks_uri": "https://k", "public_key_file": "p"}, "exactly one of"),
        ({"audience": "a", "jwks_uri": "https://k"}, "'issuer'"),
        ({"issuer": ISSUER, "jwks_uri": "https://k"}, "'audience'"),
        ({"issuer": ISSUER, "audience": "a", "jwks_uri": "https://k", "scopes": []}, "unexpected field"),
        ({"issuer": ISSUER, "audience": "a", "public_key_file": "nowhere.pem"}, "not a file"),
        ({"issuer": ISSUER, "audience": "a", "jwks_uri": "https://k", "client_secret": "s"}, "never an OAuth client"),
    ],
)
def test_a_malformed_auth_block_is_refused(tmp_path, auth, needle):
    with pytest.raises(ValueError, match=needle):
        load_config(_write(tmp_path, auth=auth))


@pytest.mark.parametrize(
    "principal, needle",
    [
        ({"roles": "x"}, "unexpected field"),
        ({"roles_claim": ""}, "dotted claim path"),
        ({"role_map": ["parent"]}, "must map"),
        ({"role_map": {"a": 1}}, "must map"),
    ],
)
def test_a_malformed_principal_block_is_refused(tmp_path, principal, needle):
    with pytest.raises(ValueError, match=needle):
        load_config(_write(tmp_path, principal=principal))


def test_create_server_builds_the_verifier_from_config(tmp_path):
    from fastmcp.server.auth.providers.jwt import JWTVerifier

    (tmp_path / "idp.pem").write_text("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n")
    config = load_config(_write(
        tmp_path, auth={"issuer": ISSUER, "audience": "extensible-mcp", "public_key_file": "idp.pem"}
    ))
    config.servers = [ServerConfig(name="mock", command=sys.executable, args=[MOCK_SERVER])]
    server = create_server(config)
    assert isinstance(server.auth, JWTVerifier)


# --------------------------------------------------------------------------- #
# End to end over HTTP: the token on the request is the principal on the call
# --------------------------------------------------------------------------- #

TOKENS = {
    "parent-token": {"client_id": "console", "scopes": [], "sub": "parent-1", "iss": ISSUER, "roles": ["parent"]},
    "nameless-token": {"client_id": "console", "scopes": [], "iss": ISSUER},
}


class _Recording:
    """One object on all three request-carrying pipelines, plus search."""

    def __init__(self) -> None:
        self.search: list[Principal | None] = []
        self.calls: list[Principal | None] = []
        self.responses: list[Principal | None] = []
        self.loads: list[Principal | None] = []

    def filter(self, results, query, *, principal=None):
        self.search.append(principal)
        return results

    async def check(self, request):
        if isinstance(request, CallRequest):
            self.calls.append(request.principal)
            return CallFilterResult(allowed=True, tool_name=request.tool_name, arguments=request.arguments)
        if isinstance(request, CallResponse):
            self.responses.append(request.principal)
            return ResponseFilterResult(allowed=True, content=request.content, is_error=request.is_error)
        assert isinstance(request, ServerLoadRequest)
        self.loads.append(request.principal)
        return ServerLoadResult(allowed=False, reason="not today")


def _config() -> Config:
    return Config(
        servers=[ServerConfig(name="mock", command=sys.executable, args=[MOCK_SERVER])],
        filters=FiltersConfig(similarity_threshold=0.0, access_control=AccessControlConfig()),
    )


@pytest.fixture
async def served():
    recording = _Recording()
    server = create_server(
        _config(),
        auth=StaticTokenVerifier(tokens=TOKENS),
        extra_search_filters=[recording],
        extra_call_filters=[recording],
        extra_response_filters=[recording],
        extra_load_filters=[recording],
    )
    async with run_server_async(server) as url:
        yield url, recording


async def test_the_verified_token_reaches_every_pipeline_as_a_principal(served):
    url, recording = served
    async with Client(StreamableHttpTransport(url, auth="parent-token")) as client:
        await client.call_tool("search_tools", {"query": "add numbers", "top_k": 3})
        result = await client.call_tool(
            "call_tool", {"tool_name": "mock__add_numbers", "arguments": {"a": 1, "b": 2}}
        )
        assert "3" in result.content[0].text
        await client.call_tool("load_mcp_server", {"server_name": "x", "url": "http://x.invalid/mcp"})

    expected = Principal(sub="parent-1", iss=ISSUER, roles=frozenset({"parent"}), client_id="console")
    assert recording.search == [expected]
    assert recording.calls == [expected]
    assert recording.responses == [expected]
    assert recording.loads == [expected]


async def test_a_request_with_no_token_never_reaches_a_handler(served):
    url, recording = served
    with pytest.raises(Exception):
        async with Client(StreamableHttpTransport(url)) as client:
            await client.call_tool("search_tools", {"query": "add numbers", "top_k": 3})
    assert recording.search == [] and recording.calls == []


async def test_a_verified_token_naming_nobody_is_an_error_not_an_anonymous_call(served):
    url, recording = served
    async with Client(StreamableHttpTransport(url, auth="nameless-token")) as client:
        result = await client.call_tool(
            "call_tool", {"tool_name": "mock__add_numbers", "arguments": {"a": 1, "b": 2}}
        )
    assert result.content[0].text.startswith("Error: the verified token carries no 'sub'")
    assert recording.calls == []


# --------------------------------------------------------------------------- #
# require_principal, and the session bound to its principal
# --------------------------------------------------------------------------- #


def test_require_principal_without_a_verifier_is_a_startup_error():
    with pytest.raises(ValueError, match="require_principal=True needs an inbound verifier"):
        create_server(_config(), require_principal=True)


async def test_require_principal_refuses_a_request_with_no_principal_ahead_of_every_pipeline():
    """The in-memory client carries no bearer, which is the stdio shape: with
    a verifier configured and the flag set, every handler refuses before any
    filter runs. Not a filter, so there is no unset-filter-permits path."""
    recording = _Recording()
    server = create_server(
        _config(),
        auth=StaticTokenVerifier(tokens=TOKENS),
        require_principal=True,
        extra_search_filters=[recording],
        extra_call_filters=[recording],
        extra_load_filters=[recording],
    )
    async with Client(server) as client:
        for tool, args in (
            ("search_tools", {"query": "add numbers", "top_k": 3}),
            ("call_tool", {"tool_name": "mock__add_numbers", "arguments": {"a": 1, "b": 2}}),
            ("load_mcp_server", {"server_name": "x", "url": "http://x.invalid/mcp"}),
        ):
            result = await client.call_tool(tool, args)
            assert result.content[0].text.startswith("Error: this proxy requires an authenticated principal")
    assert recording.search == [] and recording.calls == [] and recording.loads == []


async def test_unset_or_false_leaves_a_single_tenant_proxy_as_it_was():
    recording = _Recording()
    for flag in (None, False):
        server = create_server(_config(), require_principal=flag, extra_call_filters=[recording])
        async with Client(server) as client:
            await client.call_tool("search_tools", {"query": "add numbers", "top_k": 3})
            result = await client.call_tool(
                "call_tool", {"tool_name": "mock__add_numbers", "arguments": {"a": 1, "b": 2}}
            )
            assert "3" in result.content[0].text
    assert recording.calls == [None, None]

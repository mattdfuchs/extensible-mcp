# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Static exposure: ``tools/list`` answers with the governed catalogue, for a
platform that loads a server's tools once and dispatches them itself.

Two things are under test. First, that the mode is a *view* and not a
registration: nothing is added to the ``FastMCP`` object, and a tool called
by its listed name runs the same call path, and the same filters, as one
called through ``call_tool``. Second, that the listing is a menu and not an
allowance: who may call what is decided per call from the token on that
call, whoever listed, whenever, or never.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from fastmcp.utilities.tests import run_server_async

from extensible_mcp import LocalTool
from extensible_mcp.config import (
    AccessControlConfig,
    Config,
    FiltersConfig,
    RoleScope,
    load_config,
)
from extensible_mcp.server import create_server
from extensible_mcp.types import SearchResult, ServerConfig
from tests import vc_helpers as vc
from tests.test_bundles_from_config import (
    TRIO,
    _bundle_entry,
    _call,
    _payments_server,
)
from tests.test_minimal_bundle_differential import OVER_THE_CAP_DENIAL

MOCK_SERVER = str(Path(__file__).parent / "mock_server.py")
PAYMENTS_SERVER = str(Path(__file__).parent / "mock_payments_server.py")
META_TOOLS = {"search_tools", "call_tool", "load_mcp_server"}
MOCK_TOOLS = {"mock__add_numbers", "mock__send_email", "mock__search_files", "mock__delete_files"}
ISSUER = "https://idp.example/realms/household"
NOT_IN_CATALOGUE = "is not in this proxy's catalogue for you"


def _config(*, exposure: str = "static", deny: list[str] | None = None, payments: bool = False) -> Config:
    servers = [ServerConfig(name="mock", command=sys.executable, args=[MOCK_SERVER])]
    if payments:
        servers.append(ServerConfig(name="payments", command=sys.executable, args=[PAYMENTS_SERVER]))
    return Config(
        servers=servers,
        filters=FiltersConfig(
            similarity_threshold=0.0,
            access_control=AccessControlConfig(deny=deny or []),
        ),
        exposure=exposure,
    )


def _local_tool() -> LocalTool:
    async def handler(arguments: dict) -> dict:
        return {"sum": arguments["a"] + arguments["b"]}

    return LocalTool(
        name="local_add",
        description="Add two numbers in-process.",
        input_schema={"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}, "required": ["a", "b"]},
        handler=handler,
    )


async def _names(client: Client) -> set[str]:
    return {t.name for t in await client.list_tools()}


# --------------------------------------------------------------------------- #
# A view, not a registration.
# --------------------------------------------------------------------------- #


async def test_the_registry_still_holds_only_the_meta_tools():
    """The hazard, as a test: the listing is composed by the middleware, and
    the registry under it never gains a downstream tool."""
    server = create_server(_config(), local_tools=[_local_tool()])
    async with Client(server) as client:
        assert await _names(client) == MOCK_TOOLS | {"local_add"}
    raw = {t.name for t in await server.list_tools(run_middleware=False)}
    assert raw <= META_TOOLS


async def test_the_meta_tools_are_neither_listed_nor_callable():
    server = create_server(_config())
    async with Client(server) as client:
        assert not (await _names(client)) & META_TOOLS
        for name, args in [
            ("search_tools", {"query": "add"}),
            ("call_tool", {"tool_name": "mock__add_numbers", "arguments": {"a": 1, "b": 2}}),
            ("load_mcp_server", {"server_name": "w", "url": "http://w.invalid/mcp"}),
        ]:
            result = await client.call_tool(name, args, raise_on_error=False)
            assert result.is_error
            assert NOT_IN_CATALOGUE in result.content[0].text


async def test_a_listed_tool_is_callable_from_a_connection_that_never_listed():
    """A platform's client may open a fresh connection per call. Nothing
    about the rule depends on a list having been sent on this connection,
    or on any connection."""
    server = create_server(_config())
    async with Client(server) as client:
        result = await client.call_tool("mock__add_numbers", {"a": 1, "b": 2})
    assert not result.is_error
    assert result.content[0].text == "3"
    # The native result passes through: the downstream's structured content,
    # not the proxy's text rendering of it.
    assert result.structured_content == {"result": 3}


async def test_a_local_tool_is_listed_under_its_bare_name_and_dispatched():
    server = create_server(_config(), local_tools=[_local_tool()])
    async with Client(server) as client:
        result = await client.call_tool("local_add", {"a": 2, "b": 3})
    assert result.structured_content == {"sum": 5}


async def test_a_downstream_error_arrives_as_a_tool_error():
    server = create_server(_config())
    async with Client(server) as client:
        result = await client.call_tool("mock__add_numbers", {"a": "x", "b": 2}, raise_on_error=False)
    # The downstream refused its own arguments; its native isError result
    # passes through the response pipeline unchanged, for the model to see.
    assert result.is_error
    assert "validation" in result.content[0].text.lower() or "input" in result.content[0].text.lower()


async def test_dynamic_exposure_is_untouched():
    server = create_server(_config(exposure="dynamic"))
    async with Client(server) as client:
        assert await _names(client) == META_TOOLS
        direct = await client.call_tool("mock__add_numbers", {"a": 1, "b": 2}, raise_on_error=False)
        assert direct.is_error  # not registered, not listed, not routed
        found = await client.call_tool("search_tools", {"query": "add numbers", "top_k": 5})
        assert "mock__add_numbers" in found.content[0].text


# --------------------------------------------------------------------------- #
# The same filters, by either name.
# --------------------------------------------------------------------------- #


async def test_an_access_control_denial_is_the_same_by_either_entry_point():
    static = create_server(_config(deny=["mock__delete_files"]))
    dynamic = create_server(_config(exposure="dynamic", deny=["mock__delete_files"]))
    async with Client(static) as client:
        assert "mock__delete_files" not in await _names(client)
        direct = await client.call_tool("mock__delete_files", {"pattern": "x"}, raise_on_error=False)
    async with Client(dynamic) as client:
        await client.call_tool("search_tools", {"query": "delete files", "top_k": 5})
        via_meta = await client.call_tool(
            "call_tool", {"tool_name": "mock__delete_files", "arguments": {"pattern": "x"}}
        )
    assert direct.is_error
    assert via_meta.content[0].text == f"Error: {direct.content[0].text}"


async def test_a_name_outside_the_catalogue_is_refused_before_dispatch():
    server = create_server(_config())
    async with Client(server) as client:
        result = await client.call_tool("mock__no_such_tool", {}, raise_on_error=False)
    assert result.is_error
    assert NOT_IN_CATALOGUE in result.content[0].text


async def test_listing_and_calling_share_one_rule():
    """A custom search filter that hides a tool hides it from the list and
    from the call, with the catalogue sentence: there is one view."""

    class HideSearch:
        def filter(self, results: list[SearchResult], query: str) -> list[SearchResult]:
            return [r for r in results if r.tool.qualified_name != "mock__search_files"]

    server = create_server(_config(), extra_search_filters=[HideSearch()])
    async with Client(server) as client:
        assert "mock__search_files" not in await _names(client)
        result = await client.call_tool("mock__search_files", {"pattern": "*"}, raise_on_error=False)
    assert result.is_error
    assert NOT_IN_CATALOGUE in result.content[0].text


@pytest.fixture(scope="module")
def key():
    return vc.new_key()


def _write(tmp_path: Path, *, exposure: str, bundle: dict[str, Any]) -> Path:
    path = tmp_path / f"config-{exposure}.json"
    path.write_text(json.dumps({
        "mcpServers": {"payments": _payments_server()},
        "filters": {"similarity_threshold": 0.0, "policy_bundles": {"payments": bundle}},
        "exposure": exposure,
    }))
    return path


@pytest.mark.parametrize("engine", sorted(TRIO))
async def test_the_listed_schema_is_the_augmented_one(tmp_path, key, engine):
    """A governed tool is listed with its credential parameters, exactly as
    ``search_tools`` prints it in dynamic mode."""
    static = create_server(load_config(_write(tmp_path, exposure="static", bundle=_bundle_entry(engine, key))))
    dynamic = create_server(load_config(_write(tmp_path, exposure="dynamic", bundle=_bundle_entry(engine, key))))
    async with Client(static) as client:
        listed = {t.name: t for t in await client.list_tools()}["payments__send"]
    async with Client(dynamic) as client:
        found = await client.call_tool("search_tools", {"query": "send money", "top_k": 3})
        text = found.content[0].text
    searched = json.loads(text.split("```json\n", 1)[1].split("\n```", 1)[0])
    assert listed.input_schema == searched
    assert "requestVC" in listed.input_schema["required"]


async def test_a_bundle_denial_fires_by_the_listed_name(tmp_path, key):
    server = create_server(load_config(_write(tmp_path, exposure="static", bundle=_bundle_entry("cel", key))))
    async with Client(server) as client:
        allowed = await client.call_tool("payments__send", _call(500, key))
        # The credential was stripped: the downstream got its native arguments.
        assert allowed.content[0].text == "sent 500 to acme"

        over = await client.call_tool("payments__send", _call(5000, key), raise_on_error=False)
        assert over.is_error and over.content[0].text == OVER_THE_CAP_DENIAL

        bare = await client.call_tool("payments__send", _call(500, key, with_credential=False), raise_on_error=False)
        assert bare.is_error and "provide `requestVC`" in bare.content[0].text


async def test_single_use_fires_by_the_listed_name(tmp_path, key):
    bundle = _bundle_entry("cel", key, single_use=["requestVC"])
    server = create_server(load_config(_write(tmp_path, exposure="static", bundle=bundle)))
    async with Client(server) as client:
        args = _call(500, key)
        first = await client.call_tool("payments__send", args)
        assert first.content[0].text == "sent 500 to acme"
        again = await client.call_tool("payments__send", args, raise_on_error=False)
        assert again.is_error and "already been used" in again.content[0].text


# --------------------------------------------------------------------------- #
# A menu, not an allowance: the caller's view, per call.
# --------------------------------------------------------------------------- #

TOKENS = {
    "parent-token": {"client_id": "platform", "scopes": [], "sub": "parent-1", "iss": ISSUER, "roles": ["parent"]},
    "child-token": {"client_id": "platform", "scopes": [], "sub": "child-1", "iss": ISSUER, "roles": ["child"]},
    "guest-token": {"client_id": "platform", "scopes": [], "sub": "guest-1", "iss": ISSUER, "roles": ["guest"]},
}


def _scoped_config() -> Config:
    config = _config(payments=True)
    config.filters.access_control = AccessControlConfig(by_role={
        "parent": RoleScope(allow_servers=["mock", "payments"]),
        "child": RoleScope(allow_servers=["mock"]),
    })
    return config


async def test_each_principal_lists_and_calls_its_own_view():
    server = create_server(_scoped_config(), auth=StaticTokenVerifier(tokens=TOKENS), require_principal=True)
    async with run_server_async(server) as url:
        async with Client(StreamableHttpTransport(url, auth="parent-token")) as parent:
            assert await _names(parent) == MOCK_TOOLS | {"payments__send"}
        async with Client(StreamableHttpTransport(url, auth="child-token")) as child:
            assert await _names(child) == MOCK_TOOLS
        async with Client(StreamableHttpTransport(url, auth="guest-token")) as guest:
            # No role places the guest: nothing listed, everything refused.
            assert await _names(guest) == set()
            refused = await guest.call_tool("mock__add_numbers", {"a": 1, "b": 2}, raise_on_error=False)
            assert refused.is_error


async def test_listed_under_one_identity_called_under_another():
    """The platform listed as the parent (at activation, say) and calls as
    the child. The menu was the parent's; the answer is the child's."""
    server = create_server(_scoped_config(), auth=StaticTokenVerifier(tokens=TOKENS), require_principal=True)
    async with run_server_async(server) as url:
        async with Client(StreamableHttpTransport(url, auth="parent-token")) as parent:
            assert "payments__send" in await _names(parent)
        async with Client(StreamableHttpTransport(url, auth="child-token")) as child:
            # Never listed under the child.
            send = await child.call_tool(
                "payments__send", {"amountCents": 1, "merchant": "acme"}, raise_on_error=False
            )
            assert send.is_error and "access control" in send.content[0].text
            add = await child.call_tool("mock__add_numbers", {"a": 1, "b": 2})
            assert add.content[0].text == "3"


async def test_a_list_with_no_token_is_refused_at_the_transport():
    server = create_server(_scoped_config(), auth=StaticTokenVerifier(tokens=TOKENS), require_principal=True)
    async with run_server_async(server) as url:
        with pytest.raises(Exception):
            async with Client(StreamableHttpTransport(url)) as anonymous:
                await anonymous.list_tools()


# --------------------------------------------------------------------------- #
# Configuration and names.
# --------------------------------------------------------------------------- #


def test_exposure_defaults_to_dynamic_and_rejects_anything_else(tmp_path):
    base = {"mcpServers": {"mock": {"command": sys.executable, "args": [MOCK_SERVER]}}}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(base))
    assert load_config(path).exposure == "dynamic"
    path.write_text(json.dumps({**base, "exposure": "static"}))
    assert load_config(path).exposure == "static"
    path.write_text(json.dumps({**base, "exposure": "both"}))
    with pytest.raises(ValueError, match="'exposure' must be one of"):
        load_config(path)
    with pytest.raises(ValueError, match="'exposure' must be one of"):
        Config(exposure="both")


@pytest.mark.parametrize("name", sorted(META_TOOLS))
def test_a_local_tool_may_not_take_a_meta_tool_name(name):
    async def handler(arguments: dict) -> str:
        return ""

    with pytest.raises(ValueError, match="reserved"):
        LocalTool(name=name, description="", input_schema={}, handler=handler)

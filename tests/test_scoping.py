# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Per-role scoping: a principal's catalogue is a function of its roles, the
rule lives in ``access_control.by_role``, and present, it fails closed.

Over HTTP two people with two tokens share one proxy and one index, and
each sees and can call only what their roles allow -- the configuration
that, before this, meant one client seeing another's catalogue.
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

from extensible_mcp.config import (
    AccessControlConfig,
    Config,
    FiltersConfig,
    RoleScope,
    load_config,
)
from extensible_mcp.filters import (
    AccessControlFilter,
    ServerLoadAccessControlFilter,
    visible_servers,
)
from extensible_mcp.server import create_server
from extensible_mcp.types import (
    CallRequest,
    Principal,
    SearchResult,
    ServerConfig,
    ServerLoadRequest,
    ToolRecord,
)

MOCK_SERVER = str(Path(__file__).parent / "mock_server.py")
PAYMENTS_SERVER = str(Path(__file__).parent / "mock_payments_server.py")
ISSUER = "https://idp.example/realms/household"

BY_ROLE = {
    "parent": RoleScope(allow_servers=["payments", "pizza"], may_load=True),
    "child": RoleScope(allow_servers=["pizza"]),
    "admin": RoleScope(allow_servers="*"),
}


def _p(*roles: str) -> Principal:
    return Principal(sub="-".join(roles) or "nobody", iss=ISSUER, roles=frozenset(roles))


def _result(server: str, tool: str) -> SearchResult:
    qualified = f"{server}__{tool}" if server else tool
    return SearchResult(
        tool=ToolRecord(name=tool, qualified_name=qualified, description="", input_schema={}, server_name=server),
        score=1.0,
    )


def _names(results) -> set[str]:
    return {r.tool.qualified_name for r in results}


CATALOGUE = [
    _result("payments", "spend"),
    _result("pizza", "order_pizza"),
    _result("settlement", "charge_invoice"),
    _result("", "request_action_vc"),  # a local tool
]


# --------------------------------------------------------------------------- #
# The rule
# --------------------------------------------------------------------------- #


def test_roles_are_additive():
    assert visible_servers(BY_ROLE, _p("child")) == {"pizza"}
    assert visible_servers(BY_ROLE, _p("parent")) == {"payments", "pizza"}
    assert visible_servers(BY_ROLE, _p("child", "parent")) == {"payments", "pizza"}
    assert visible_servers(BY_ROLE, _p("admin", "child")) is None  # every server


def test_no_matching_role_and_no_principal_see_nothing():
    assert visible_servers(BY_ROLE, _p("guest")) == set()
    assert visible_servers(BY_ROLE, None) == set()


def test_the_search_filter_scopes_the_catalogue_per_principal():
    ac = AccessControlFilter(deny=["pizza__cancel_order"], by_role=BY_ROLE)
    assert _names(ac.filter(CATALOGUE, "q", principal=_p("child"))) == {"pizza__order_pizza", "request_action_vc"}
    assert _names(ac.filter(CATALOGUE, "q", principal=_p("parent"))) == {
        "payments__spend", "pizza__order_pizza", "request_action_vc",
    }
    assert _names(ac.filter(CATALOGUE, "q", principal=_p("admin"))) == _names(CATALOGUE)
    # Fail closed: nothing, local tools included.
    assert ac.filter(CATALOGUE, "q", principal=_p("guest")) == []
    assert ac.filter(CATALOGUE, "q", principal=None) == []
    assert ac.filter(CATALOGUE, "q") == []


def test_the_global_deny_is_a_floor_for_every_role():
    ac = AccessControlFilter(deny=["pizza__order_pizza"], by_role=BY_ROLE)
    assert _names(ac.filter(CATALOGUE, "q", principal=_p("admin"))) == {
        "payments__spend", "settlement__charge_invoice", "request_action_vc",
    }


def test_without_by_role_nothing_is_keyed_on_the_principal():
    ac = AccessControlFilter(deny=["pizza__cancel_order"])
    assert _names(ac.filter(CATALOGUE, "q", principal=None)) == _names(CATALOGUE)
    assert _names(ac.filter(CATALOGUE, "q", principal=_p("guest"))) == _names(CATALOGUE)


async def test_the_call_filter_applies_the_same_rule():
    ac = AccessControlFilter(by_role=BY_ROLE)

    async def allowed(server: str, tool: str, principal) -> bool:
        request = CallRequest(
            tool_name=f"{server}__{tool}" if server else tool, arguments={},
            server_name=server, principal=principal,
        )
        return (await ac.check(request)).allowed

    assert await allowed("pizza", "order_pizza", _p("child"))
    assert not await allowed("payments", "spend", _p("child"))
    assert await allowed("", "request_action_vc", _p("child"))
    assert not await allowed("", "request_action_vc", _p("guest"))
    assert not await allowed("pizza", "order_pizza", None)


async def test_may_load_gates_runtime_loading_per_role():
    lc = ServerLoadAccessControlFilter(by_role=BY_ROLE)

    async def allowed(principal) -> bool:
        return (await lc.check(ServerLoadRequest(server_name="x", url="https://x.example/mcp", principal=principal))).allowed

    assert await allowed(_p("parent"))
    assert not await allowed(_p("child"))
    assert not await allowed(_p("admin"))  # "*" is visibility, not permission to load
    assert not await allowed(None)
    # Without by_role the load filter keeps its URL/name rules only.
    assert (await ServerLoadAccessControlFilter().check(
        ServerLoadRequest(server_name="x", url="https://x.example/mcp")
    )).allowed


def test_a_loaded_server_is_visible_to_the_roles_that_name_it_or_see_everything():
    """Runtime-loaded servers are indexed once for the process; a name no role
    lists is visible to the '*' role alone."""
    ac = AccessControlFilter(by_role=BY_ROLE)
    loaded = _result("weather", "forecast")
    assert ac.filter([loaded], "q", principal=_p("admin")) == [loaded]
    assert ac.filter([loaded], "q", principal=_p("parent")) == []


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #


def _write(tmp_path: Path, access_control: dict[str, Any]) -> Path:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"mcpServers": {"m": {"command": "x"}}, "filters": {"access_control": access_control}}))
    return path


def test_by_role_parses_to_role_scopes(tmp_path):
    config = load_config(_write(tmp_path, {
        "by_role": {"parent": {"allow_servers": ["m"], "may_load": True}, "admin": {"allow_servers": "*"}}
    }))
    assert config.filters.access_control.by_role == {
        "parent": RoleScope(allow_servers=["m"], may_load=True),
        "admin": RoleScope(allow_servers="*", may_load=False),
    }
    assert load_config(_write(tmp_path, {})).filters.access_control.by_role is None


@pytest.mark.parametrize(
    "by_role, needle",
    [
        ({}, "non-empty object"),
        ([], "non-empty object"),
        ({"parent": ["m"]}, "must be an object"),
        ({"parent": {"allow_servers": ["m"], "deny": []}}, "unexpected field"),
        ({"parent": {"may_load": True}}, "allow_servers"),
        ({"parent": {"allow_servers": "all"}}, "allow_servers"),
        ({"parent": {"allow_servers": ["m"], "may_load": "yes"}}, "boolean"),
    ],
)
def test_a_malformed_by_role_is_refused(tmp_path, by_role, needle):
    with pytest.raises(ValueError, match=needle):
        load_config(_write(tmp_path, {"by_role": by_role}))


# --------------------------------------------------------------------------- #
# End to end: two people, one proxy, one index
# --------------------------------------------------------------------------- #

TOKENS = {
    "parent-token": {"client_id": "console", "scopes": [], "sub": "parent-1", "iss": ISSUER, "roles": ["parent"]},
    "child-token": {"client_id": "console", "scopes": [], "sub": "child-1", "iss": ISSUER, "roles": ["child"]},
    "guest-token": {"client_id": "console", "scopes": [], "sub": "guest-1", "iss": ISSUER, "roles": ["guest"]},
}


def _config() -> Config:
    return Config(
        servers=[
            ServerConfig(name="mock", command=sys.executable, args=[MOCK_SERVER]),
            ServerConfig(name="payments", command=sys.executable, args=[PAYMENTS_SERVER]),
        ],
        filters=FiltersConfig(
            similarity_threshold=0.0,
            access_control=AccessControlConfig(by_role={
                "parent": RoleScope(allow_servers=["mock", "payments"], may_load=True),
                "child": RoleScope(allow_servers=["mock"]),
            }),
        ),
    )


async def _as(url: str, token: str):
    async with Client(StreamableHttpTransport(url, auth=token)) as client:
        found = await client.call_tool("search_tools", {"query": "add numbers send money", "top_k": 10})
        text = found.content[0].text
        add = await client.call_tool("call_tool", {"tool_name": "mock__add_numbers", "arguments": {"a": 1, "b": 2}})
        send = await client.call_tool(
            "call_tool", {"tool_name": "payments__send", "arguments": {"amountCents": 1, "merchant": "acme"}}
        )
        load = await client.call_tool("load_mcp_server", {"server_name": "w", "url": "http://w.invalid/mcp"})
        return text, add.content[0].text, send.content[0].text, load.content[0].text


async def test_two_principals_one_proxy_each_see_only_their_catalogue():
    server = create_server(_config(), auth=StaticTokenVerifier(tokens=TOKENS), require_principal=True)
    async with run_server_async(server) as url:
        # Runtime loading is refused over HTTP for every role in this release,
        # ahead of the load pipeline, so may_load does not distinguish the
        # parent from the child here; the filter-level test above covers it.
        http_refusal = "Error: load_mcp_server is not available over HTTP"

        text, add, send, load = await _as(url, "parent-token")
        assert "mock__add_numbers" in text and "payments__send" in text
        assert "3" in add and send.startswith("sent 1")
        assert load.startswith(http_refusal)

        text, add, send, load = await _as(url, "child-token")
        assert "mock__add_numbers" in text and "payments__send" not in text
        assert "3" in add
        assert send.startswith("Error:") and "access control" in send
        assert load.startswith(http_refusal)

        text, add, send, load = await _as(url, "guest-token")
        assert "mock__" not in text and "payments__" not in text
        assert add.startswith("Error:") and send.startswith("Error:") and load.startswith("Error:")

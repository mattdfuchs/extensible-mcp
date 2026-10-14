# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The call-path invariants, enumerated rather than described.

Three rules hold the call path together, and until this file all three were
prose -- in CLAUDE.md's "central invariant" section and the README's threat
model. Prose does not fail. The call path is deny-on-objection, so a control
that silently loses its key *permits*: correctness here cannot be established
by careful reading, which is why each rule is a test that fails loudly.

The invariants, one section each:

1. the registered-tool set is closed -- exactly the three meta-tools, ever;
2. every field of a request reaches every filter in its pipeline;
3. a server the selector cannot place is refused, not admitted ungoverned.
"""

from __future__ import annotations

import sys
from pathlib import Path

from fastmcp import Client

from extensible_mcp.config import Config, FiltersConfig
from extensible_mcp.routing import BundleRouter
from extensible_mcp.selection import LayeredBundleSelector
from extensible_mcp.server import create_server
from extensible_mcp.types import CallFilterResult, LocalTool, ServerConfig

MOCK_SERVER_PATH = str(Path(__file__).parent / "mock_server.py")


# --------------------------------------------------------------------------- #
# 1. The registered-tool set is closed.
#
# A tool registered directly on the FastMCP object is reachable by name and
# subject to nothing -- not access control, not a policy bundle, not even the
# rule that a tool must have been surfaced by search_tools, because every
# filter runs inside call_tool_handler and nothing else in the process gates a
# call. That was a live hole until `local_tools` closed it. This section is
# what keeps it closed: the set is asserted to be exactly the three meta-tools,
# so reintroducing a `@server.tool()` after `create_server` returns fails here
# rather than passing review.
# --------------------------------------------------------------------------- #

META_TOOLS = {"search_tools", "call_tool", "load_mcp_server"}


def _config() -> Config:
    """A config with no downstream servers.

    Nothing is connected and no index is built: `list_tools` below reads the
    registry on the returned object without entering the lifespan, which is
    the question this section asks -- what is *registered*, not what a running
    proxy can reach.
    """
    return Config(servers=[], filters=FiltersConfig(similarity_threshold=0.0))


async def _registered_tool_names(server) -> set[str]:
    return {t.name for t in await server.list_tools()}


async def test_registered_tools_are_exactly_the_three_meta_tools():
    server = create_server(_config())
    assert await _registered_tool_names(server) == META_TOOLS


async def test_local_tools_register_no_tool_on_the_server():
    """`local_tools` must stay invisible to the MCP tool list.

    A local tool is reached through `call_tool` -- and so through every
    CallFilter -- precisely because it is *not* registered as a tool of its
    own. If one ever shows up here, it has a second, unfiltered call path.
    """

    async def handler(arguments: dict) -> str:
        return "ok"

    locals_ = [
        LocalTool(
            name=name,
            description=f"local tool {name}",
            input_schema={"type": "object", "properties": {}},
            handler=handler,
        )
        for name in ("approve_payment", "read_wallet")
    ]
    server = create_server(_config(), local_tools=locals_)
    assert await _registered_tool_names(server) == META_TOOLS


async def test_filters_and_bundle_router_register_no_tools():
    """None of the embedding hooks may add a tool.

    The extra_*_filters and bundle_router kwargs are the supported extension
    points; a third party reaching for one of them must not be able to widen
    the reachable surface as a side effect.
    """

    class _PassThroughCallFilter:
        async def check(self, request):
            return CallFilterResult(
                allowed=True,
                tool_name=request.tool_name,
                arguments=request.arguments,
            )

    class _PassThroughSearchFilter:
        def filter(self, results, query):
            return results

    router = BundleRouter(LayeredBundleSelector(), lambda bundle: None)
    server = create_server(
        _config(),
        extra_search_filters=[_PassThroughSearchFilter()],
        extra_call_filters=[_PassThroughCallFilter()],
        bundle_router=router,
    )
    assert await _registered_tool_names(server) == META_TOOLS


async def test_three_meta_tools_are_registered_on_a_live_proxy():
    """The same set, through a client against a connected proxy.

    The registry checks above do not enter the lifespan; this one does, so a
    tool registered from inside it -- at connect time, per downstream server --
    would be caught as well.
    """
    config = Config(
        servers=[
            ServerConfig(name="mock", command=sys.executable, args=[MOCK_SERVER_PATH])
        ],
        filters=FiltersConfig(similarity_threshold=0.0),
    )
    server = create_server(config)
    async with Client(server) as client:
        assert {t.name for t in await client.list_tools()} == META_TOOLS

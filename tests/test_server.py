"""Integration tests for the full proxy server flow."""

import sys
from pathlib import Path

import pytest
from fastmcp import Client

from extensible_mcp.config import Config, AccessControlConfig, FiltersConfig, LoadControlConfig
from extensible_mcp.server import create_server
from extensible_mcp.types import ServerConfig


MOCK_SERVER_PATH = str(Path(__file__).parent / "mock_server.py")


def _make_config(
    deny: list[str] | None = None,
    load_control: LoadControlConfig | None = None,
    rego_policy: str | None = None,
) -> Config:
    return Config(
        servers=[
            ServerConfig(
                name="mock",
                command=sys.executable,
                args=[MOCK_SERVER_PATH],
            )
        ],
        filters=FiltersConfig(
            similarity_threshold=0.0,
            access_control=AccessControlConfig(
                deny=deny or [],
                deny_patterns=[],
                allow_servers=[],
            ),
            rego_policy=rego_policy,
            load_control=load_control or LoadControlConfig(),
        ),
    )


@pytest.mark.asyncio
async def test_proxy_lists_two_tools():
    """Proxy should expose exactly search_tools and call_tool."""
    server = create_server(_make_config())
    async with Client(server) as client:
        tools = await client.list_tools()
        tool_names = {t.name for t in tools}
        assert tool_names == {"search_tools", "call_tool", "load_mcp_server"}


@pytest.mark.asyncio
async def test_search_and_call_roundtrip():
    """Search for a tool, then call it through the proxy."""
    server = create_server(_make_config())
    async with Client(server) as client:
        # Search
        search_result = await client.call_tool("search_tools", {"query": "add numbers", "top_k": 3})
        search_text = search_result.content[0].text
        assert "mock__add_numbers" in search_text

        # Call
        call_result = await client.call_tool(
            "call_tool",
            {"tool_name": "mock__add_numbers", "arguments": {"a": 10, "b": 20}},
        )
        assert "30" in call_result.content[0].text


@pytest.mark.asyncio
async def test_access_control_blocks_denied_tool():
    """Denied tools should be blocked in call_tool."""
    server = create_server(_make_config(deny=["mock__delete_files"]))
    async with Client(server) as client:
        result = await client.call_tool(
            "call_tool",
            {"tool_name": "mock__delete_files", "arguments": {"pattern": "*"}},
        )
        assert "blocked" in result.content[0].text.lower()


@pytest.mark.asyncio
async def test_call_rejected_without_prior_search():
    """Calling a tool without searching first should be rejected by DiscoveredToolsFilter."""
    server = create_server(_make_config())
    async with Client(server) as client:
        result = await client.call_tool(
            "call_tool",
            {"tool_name": "mock__add_numbers", "arguments": {"a": 1, "b": 2}},
        )
        text = result.content[0].text
        assert "not been discovered" in text.lower()


@pytest.mark.asyncio
async def test_call_allowed_after_search():
    """Calling a tool after discovering it via search_tools should succeed."""
    server = create_server(_make_config())
    async with Client(server) as client:
        # Search first to discover the tool
        await client.call_tool("search_tools", {"query": "add numbers", "top_k": 3})
        # Now the call should work
        result = await client.call_tool(
            "call_tool",
            {"tool_name": "mock__add_numbers", "arguments": {"a": 5, "b": 7}},
        )
        assert "12" in result.content[0].text


@pytest.mark.asyncio
async def test_load_mcp_server_rejected_by_load_control():
    """load_mcp_server should reject URLs blocked by load_control policy."""
    lc = LoadControlConfig(deny_url_patterns=["http://*"])
    server = create_server(_make_config(load_control=lc))
    async with Client(server) as client:
        result = await client.call_tool(
            "load_mcp_server",
            {"server_name": "evil", "url": "http://evil.example.com/mcp"},
        )
        text = result.content[0].text
        assert "error" in text.lower()
        assert "http://evil.example.com/mcp" in text


@pytest.mark.asyncio
async def test_extra_call_filter_runs_after_builtins():
    """User-supplied CallFilter passed via create_server kwargs should be invoked."""
    from extensible_mcp import CallFilterResult

    invoked: list[str] = []

    class TrackingFilter:
        async def check(self, request):
            invoked.append(request.tool_name)
            return CallFilterResult(
                allowed=True,
                tool_name=request.tool_name,
                arguments=request.arguments,
            )

    server = create_server(_make_config(), extra_call_filters=[TrackingFilter()])
    async with Client(server) as client:
        await client.call_tool("search_tools", {"query": "add numbers", "top_k": 3})
        await client.call_tool(
            "call_tool",
            {"tool_name": "mock__add_numbers", "arguments": {"a": 1, "b": 2}},
        )
        assert invoked == ["mock__add_numbers"]


@pytest.mark.asyncio
async def test_extra_call_filter_can_deny():
    """User-supplied CallFilter returning allowed=False should block the call."""
    from extensible_mcp import CallFilterResult

    class BlockingFilter:
        async def check(self, request):
            return CallFilterResult(
                allowed=False,
                reason="blocked by custom policy",
                tool_name=request.tool_name,
                arguments=request.arguments,
            )

    server = create_server(_make_config(), extra_call_filters=[BlockingFilter()])
    async with Client(server) as client:
        await client.call_tool("search_tools", {"query": "add numbers", "top_k": 3})
        result = await client.call_tool(
            "call_tool",
            {"tool_name": "mock__add_numbers", "arguments": {"a": 1, "b": 2}},
        )
        assert "blocked by custom policy" in result.content[0].text


try:
    import regopy  # noqa: F401
    HAS_REGOPY = True
except ImportError:
    HAS_REGOPY = False

REGO_POLICY_PATH = str(Path(__file__).parent / "policies" / "deny_delete.rego")


@pytest.mark.skipif(not HAS_REGOPY, reason="regopy not installed")
@pytest.mark.asyncio
async def test_rego_policy_blocks_call():
    """Rego policy should block a matching tool call after search."""
    server = create_server(_make_config(rego_policy=REGO_POLICY_PATH))
    async with Client(server) as client:
        # Search first to discover the tool
        await client.call_tool("search_tools", {"query": "delete files", "top_k": 5})
        # Call should be blocked by Rego
        result = await client.call_tool(
            "call_tool",
            {"tool_name": "mock__delete_files", "arguments": {"pattern": "*"}},
        )
        text = result.content[0].text
        assert "delete operations are not allowed" in text.lower()

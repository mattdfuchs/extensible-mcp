"""Integration tests for the full proxy server flow."""

import sys
from pathlib import Path

import pytest
from fastmcp import Client

from extensible_mcp.config import Config, AccessControlConfig, FiltersConfig
from extensible_mcp.server import create_server
from extensible_mcp.types import ServerConfig


MOCK_SERVER_PATH = str(Path(__file__).parent / "mock_server.py")


def _make_config(deny: list[str] | None = None) -> Config:
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

"""Integration tests for the full proxy server flow."""

import sys
from pathlib import Path

import pytest
from fastmcp import Client

from extensible_mcp.config import Config, AccessControlConfig, FiltersConfig, LoadControlConfig, ToolPolicyConfig
from extensible_mcp.server import create_server
from extensible_mcp.types import ServerConfig


MOCK_SERVER_PATH = str(Path(__file__).parent / "mock_server.py")


def _make_config(
    deny: list[str] | None = None,
    call_policies: list[ToolPolicyConfig] | None = None,
    load_control: LoadControlConfig | None = None,
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
            call_policies=call_policies or [],
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
async def test_policy_rejects_call_without_required_argument():
    """A call_policy should reject a call when the required argument is missing."""
    policy = ToolPolicyConfig(
        tool_pattern="*__delete_*",
        required_arguments={"confirmation": "CONFIRM_DELETE"},
    )
    server = create_server(_make_config(call_policies=[policy]))
    async with Client(server) as client:
        result = await client.call_tool(
            "call_tool",
            {"tool_name": "mock__delete_files", "arguments": {"pattern": "*"}},
        )
        text = result.content[0].text
        assert "error" in text.lower()
        assert "confirmation" in text.lower()


@pytest.mark.asyncio
async def test_policy_allows_call_with_required_argument():
    """A call_policy should allow a call when the required argument is present."""
    policy = ToolPolicyConfig(
        tool_pattern="*__delete_*",
        required_arguments={"confirmation": "CONFIRM_DELETE"},
    )
    server = create_server(_make_config(call_policies=[policy]))
    async with Client(server) as client:
        result = await client.call_tool(
            "call_tool",
            {
                "tool_name": "mock__delete_files",
                "arguments": {"pattern": "*", "confirmation": "CONFIRM_DELETE"},
            },
        )
        text = result.content[0].text
        assert "deleted" in text.lower()


@pytest.mark.asyncio
async def test_search_results_include_security_requirements():
    """When a policy matches, search results should include requirement text."""
    policy = ToolPolicyConfig(
        tool_pattern="*__delete_*",
        required_arguments={"confirmation": "CONFIRM_DELETE"},
    )
    server = create_server(_make_config(call_policies=[policy]))
    async with Client(server) as client:
        result = await client.call_tool(
            "search_tools", {"query": "delete files", "top_k": 5}
        )
        text = result.content[0].text
        assert "SECURITY REQUIREMENTS" in text
        assert "confirmation" in text


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

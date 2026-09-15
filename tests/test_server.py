# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

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


@pytest.mark.asyncio
async def test_extra_response_filter_modifies_output():
    """A user-supplied ResponseFilter can rewrite the content the LLM sees."""
    import mcp.types as mcp_types
    from extensible_mcp import CallResponse, ResponseFilterResult

    class Redactor:
        async def check(self, response):
            new_content = []
            for block in response.content:
                if isinstance(block, mcp_types.TextContent):
                    new_content.append(
                        mcp_types.TextContent(
                            type="text",
                            text=block.text.replace("30", "[REDACTED]"),
                        )
                    )
                else:
                    new_content.append(block)
            return ResponseFilterResult(
                allowed=True,
                content=new_content,
                is_error=response.is_error,
            )

    server = create_server(_make_config(), extra_response_filters=[Redactor()])
    async with Client(server) as client:
        await client.call_tool("search_tools", {"query": "add numbers", "top_k": 3})
        result = await client.call_tool(
            "call_tool",
            {"tool_name": "mock__add_numbers", "arguments": {"a": 10, "b": 20}},
        )
        text = result.content[0].text
        assert "[REDACTED]" in text
        assert "30" not in text


@pytest.mark.asyncio
async def test_extra_response_filter_can_deny():
    """A ResponseFilter returning allowed=False replaces the result with an error."""
    from extensible_mcp import ResponseFilterResult

    class BlockingResponseFilter:
        async def check(self, response):
            return ResponseFilterResult(
                allowed=False,
                reason="response blocked: contained sensitive data",
                content=response.content,
                is_error=response.is_error,
            )

    server = create_server(
        _make_config(), extra_response_filters=[BlockingResponseFilter()]
    )
    async with Client(server) as client:
        await client.call_tool("search_tools", {"query": "add numbers", "top_k": 3})
        result = await client.call_tool(
            "call_tool",
            {"tool_name": "mock__add_numbers", "arguments": {"a": 1, "b": 2}},
        )
        text = result.content[0].text
        assert "response blocked: contained sensitive data" in text


@pytest.mark.asyncio
async def test_extra_response_filter_runs_after_call_filter():
    """Response filter only sees a successful call; rejected calls don't reach it."""
    from extensible_mcp import ResponseFilterResult

    invoked: list[str] = []

    class TrackingResponseFilter:
        async def check(self, response):
            invoked.append(response.tool_name)
            return ResponseFilterResult(
                allowed=True,
                content=response.content,
                is_error=response.is_error,
            )

    # Call filter denies upfront via the access-control deny list.
    server = create_server(
        _make_config(deny=["mock__add_numbers"]),
        extra_response_filters=[TrackingResponseFilter()],
    )
    async with Client(server) as client:
        await client.call_tool("search_tools", {"query": "add numbers", "top_k": 3})
        await client.call_tool(
            "call_tool",
            {"tool_name": "mock__add_numbers", "arguments": {"a": 1, "b": 2}},
        )
        # The call was blocked at the call-filter stage; response filter never ran.
        assert invoked == []


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


def _make_add_local_tool():
    from extensible_mcp import LocalTool

    async def handler(arguments: dict) -> dict:
        return {"sum": arguments["a"] + arguments["b"]}

    return LocalTool(
        name="local_add_numbers",
        description="Add two numbers (in-process, not a downstream tool).",
        input_schema={
            "type": "object",
            "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
            "required": ["a", "b"],
        },
        handler=handler,
    )


@pytest.mark.asyncio
async def test_local_tool_absent_from_list_but_found_by_search():
    """A local tool is dispatched like a downstream one, not listed like one:
    it never appears in list_tools() (same as every downstream tool), but
    search_tools finds it exactly like a downstream tool would."""
    server = create_server(_make_config(), local_tools=[_make_add_local_tool()])
    async with Client(server) as client:
        tools = await client.list_tools()
        assert {t.name for t in tools} == {"search_tools", "call_tool", "load_mcp_server"}

        search_result = await client.call_tool("search_tools", {"query": "add two numbers", "top_k": 5})
        assert "local_add_numbers" in search_result.content[0].text


@pytest.mark.asyncio
async def test_local_tool_rejected_without_prior_search():
    """DiscoveredToolsFilter gates a local tool exactly like a downstream one."""
    server = create_server(_make_config(), local_tools=[_make_add_local_tool()])
    async with Client(server) as client:
        result = await client.call_tool(
            "call_tool", {"tool_name": "local_add_numbers", "arguments": {"a": 1, "b": 2}}
        )
        assert "not been discovered" in result.content[0].text.lower()


@pytest.mark.asyncio
async def test_local_tool_dispatches_after_search():
    """After search_tools discovers it, call_tool dispatches to the local
    handler directly — no downstream MCP round trip involved."""
    server = create_server(_make_config(), local_tools=[_make_add_local_tool()])
    async with Client(server) as client:
        await client.call_tool("search_tools", {"query": "add two numbers", "top_k": 5})
        result = await client.call_tool(
            "call_tool", {"tool_name": "local_add_numbers", "arguments": {"a": 5, "b": 7}}
        )
        assert "12" in result.content[0].text


@pytest.mark.asyncio
async def test_local_tool_can_be_denied_by_name():
    """AccessControlFilter's deny list applies to local tools by name too."""
    server = create_server(
        _make_config(deny=["local_add_numbers"]), local_tools=[_make_add_local_tool()]
    )
    async with Client(server) as client:
        result = await client.call_tool(
            "call_tool", {"tool_name": "local_add_numbers", "arguments": {"a": 1, "b": 2}}
        )
        assert "blocked" in result.content[0].text.lower()


@pytest.mark.asyncio
async def test_local_tool_exempt_from_allow_servers():
    """allow_servers scopes downstream MCP servers only — a local tool
    (server_name="") must not be silently blocked by it, even when the only
    configured downstream server is itself in the allow-list."""
    config = Config(
        servers=[
            ServerConfig(name="mock", command=sys.executable, args=[MOCK_SERVER_PATH]),
        ],
        filters=FiltersConfig(
            similarity_threshold=0.0,
            access_control=AccessControlConfig(allow_servers=["mock"]),
        ),
    )
    server = create_server(config, local_tools=[_make_add_local_tool()])
    async with Client(server) as client:
        await client.call_tool("search_tools", {"query": "add two numbers", "top_k": 5})
        result = await client.call_tool(
            "call_tool", {"tool_name": "local_add_numbers", "arguments": {"a": 3, "b": 4}}
        )
        assert "7" in result.content[0].text


@pytest.mark.asyncio
async def test_load_mcp_server_rejects_separator_in_name():
    """A server named with `__` would re-parse as a different server at call
    time, escaping per-server policy routing and call-side access control."""
    server = create_server(_make_config())
    async with Client(server) as client:
        result = await client.call_tool(
            "load_mcp_server",
            {"server_name": "acme__pay", "url": "https://example.com/mcp"},
        )
        assert "must not contain" in result.content[0].text


def test_server_config_rejects_separator_in_name():
    with pytest.raises(ValueError, match="must not contain"):
        ServerConfig(name="acme__pay", url="https://example.com/mcp")


def test_local_tool_rejects_separator_in_name():
    from extensible_mcp import LocalTool

    async def handler(arguments: dict) -> dict:
        return {}

    with pytest.raises(ValueError, match="must not contain"):
        LocalTool(
            name="acme__pay",
            description="x",
            input_schema={"type": "object"},
            handler=handler,
        )

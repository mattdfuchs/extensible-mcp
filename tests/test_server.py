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


def test_describe_unwraps_exception_groups():
    """anyio task groups wrap the real failure, so a refused connection
    reached the LLM as 'unhandled errors in a TaskGroup (1 sub-exception)'."""
    from extensible_mcp.server import _describe

    inner = ConnectionRefusedError("All connection attempts failed")
    assert _describe(inner) == "All connection attempts failed"

    wrapped = ExceptionGroup("unhandled errors in a TaskGroup", [inner])
    assert _describe(wrapped) == "All connection attempts failed"

    nested = ExceptionGroup("outer", [ExceptionGroup("inner", [inner])])
    assert _describe(nested) == "All connection attempts failed"

    several = ExceptionGroup("outer", [inner, ValueError("bad url")])
    assert _describe(several) == "All connection attempts failed; bad url"

    # An exception carrying no message still names itself.
    assert _describe(ExceptionGroup("outer", [RuntimeError()])) == "RuntimeError"


# -- the discovery rule is per session, not per process ---------------------- #
#
# Reported 2026-09-28 against the public repo, as an in-scope bypass of the
# "can only call what it surfaced" property. A single shared set turned the
# guarantee into "anything anyone connected to this proxy has ever surfaced" --
# a monotonically growing global allowlist. On stdio one process serves one
# client, so it made no difference there; on an HTTP transport serving several
# sessions it was real.


@pytest.mark.asyncio
async def test_one_session_cannot_call_what_another_discovered():
    """The bypass, end to end: two clients on one proxy. A searches, B calls."""
    server = create_server(_make_config())
    async with Client(server) as client_a, Client(server) as client_b:
        found = await client_a.call_tool(
            "search_tools", {"query": "add numbers", "top_k": 3}
        )
        assert "mock__add_numbers" in found.content[0].text

        # A may call it, having surfaced it.
        allowed = await client_a.call_tool(
            "call_tool",
            {"tool_name": "mock__add_numbers", "arguments": {"a": 5, "b": 7}},
        )
        assert "12" in allowed.content[0].text

        # B never searched, and must not inherit A's discovery.
        refused = await client_b.call_tool(
            "call_tool",
            {"tool_name": "mock__add_numbers", "arguments": {"a": 5, "b": 7}},
        )
        assert "not been discovered" in refused.content[0].text.lower()


@pytest.mark.asyncio
async def test_each_session_keeps_its_own_discoveries():
    """Scoping must not break the normal case: both sessions search, both call."""
    server = create_server(_make_config())
    async with Client(server) as client_a, Client(server) as client_b:
        for client in (client_a, client_b):
            await client.call_tool("search_tools", {"query": "add numbers", "top_k": 3})
        for client in (client_a, client_b):
            result = await client.call_tool(
                "call_tool",
                {"tool_name": "mock__add_numbers", "arguments": {"a": 1, "b": 2}},
            )
            assert "3" in result.content[0].text


def test_the_filter_scopes_by_session_and_evicts_safely():
    """Unit-level: the store is per session, and bounded.

    Eviction is the safe direction here -- forgetting a discovery denies a call
    that would have been allowed -- so flooding the proxy with sessions
    restricts others rather than freeing them.
    """
    from extensible_mcp.filters import DiscoveredToolsFilter

    f = DiscoveredToolsFilter(max_sessions=2)
    f.register(["a__x"], "s1")
    f.register(["b__y"], "s2")
    assert f.discovered_for("s1") == {"a__x"}
    assert f.discovered_for("s2") == {"b__y"}
    assert f.discovered_for("s3") == set()

    f.register(["c__z"], "s3")          # over the bound: evicts s1, the oldest
    assert f.discovered_for("s1") == set()
    assert f.discovered_for("s3") == {"c__z"}


def test_a_sessionless_transport_still_works():
    """stdio has no session, so those calls share one bucket -- which is the
    single-client case the guarantee was written for."""
    from extensible_mcp.filters import DiscoveredToolsFilter

    f = DiscoveredToolsFilter()
    f.register(["a__x"])
    assert f.discovered_for() == {"a__x"}
    assert f.discovered_for(None) == {"a__x"}

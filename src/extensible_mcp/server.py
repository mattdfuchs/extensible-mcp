from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from fastmcp import FastMCP, Context
from fastmcp.server.lifespan import lifespan
import mcp.types as mcp_types

from .client_manager import ClientManager
from .config import Config, find_config_path, load_config
from .filters import (
    AccessControlFilter,
    CallFilterPipeline,
    FilterPipeline,
    RequirementInjectionFilter,
    RequirementValidationFilter,
    ServerLoadAccessControlFilter,
    ServerLoadFilterPipeline,
    SimilarityThresholdFilter,
)
from .types import CallRequest, ServerLoadRequest, ToolPolicy
from .vector_store import VectorStore

logging.basicConfig(stream=sys.stderr, level=logging.INFO)
logger = logging.getLogger(__name__)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extensible MCP Proxy")
    parser.add_argument("--config", type=str, default=None, help="Path to config file")
    return parser.parse_args()


def _build_pipelines(
    config: Config,
) -> tuple[FilterPipeline, CallFilterPipeline, ServerLoadFilterPipeline]:
    ac = AccessControlFilter(
        deny=config.filters.access_control.deny,
        deny_patterns=config.filters.access_control.deny_patterns,
        allow_servers=config.filters.access_control.allow_servers or None,
    )

    policies = [
        ToolPolicy(
            tool_pattern=p.tool_pattern,
            required_arguments=p.required_arguments,
        )
        for p in config.filters.call_policies
    ]

    search_pipeline = FilterPipeline([
        SimilarityThresholdFilter(config.filters.similarity_threshold),
        ac,
    ])
    if policies:
        search_pipeline.add(RequirementInjectionFilter(policies))

    call_pipeline = CallFilterPipeline([ac])
    if policies:
        call_pipeline.add(RequirementValidationFilter(policies))

    lc = config.filters.load_control
    server_load_pipeline = ServerLoadFilterPipeline()
    if lc.deny_names or lc.deny_name_patterns or lc.deny_url_patterns or lc.allow_url_patterns:
        server_load_pipeline.add(ServerLoadAccessControlFilter(
            deny_names=lc.deny_names,
            deny_name_patterns=lc.deny_name_patterns,
            deny_url_patterns=lc.deny_url_patterns,
            allow_url_patterns=lc.allow_url_patterns,
        ))

    return search_pipeline, call_pipeline, server_load_pipeline


def _format_search_results(results: list[Any]) -> str:
    if not results:
        return "No matching tools found. Try a different search query."
    lines: list[str] = []
    for r in results:
        tool = r.tool
        lines.append(f"## {tool.qualified_name}")
        lines.append(f"**Description:** {tool.description}")
        lines.append(f"**Parameters:**")
        lines.append(f"```json\n{json.dumps(tool.input_schema, indent=2)}\n```")
        lines.append(f"**Similarity:** {r.score:.3f}")
        lines.append("")
    header = (
        f"Found {len(results)} matching tool(s). "
        "Use `call_tool` with the tool name and arguments to invoke one.\n\n"
    )
    return header + "\n".join(lines)


async def _setup(config: Config) -> dict[str, Any]:
    """Connect to downstream servers, build vector index, return lifespan context."""
    search_pipeline, call_pipeline, server_load_pipeline = _build_pipelines(config)

    client_mgr = ClientManager()
    logger.info("Connecting to %d downstream server(s)...", len(config.servers))
    tools = await client_mgr.connect_all(config.servers)
    logger.info("Indexed %d tools total", len(tools))

    vector_store = VectorStore()
    logger.info("Building vector index...")
    vector_store.index(tools)
    logger.info("Vector index ready")

    return {
        "vector_store": vector_store,
        "filter_pipeline": search_pipeline,
        "call_filter_pipeline": call_pipeline,
        "server_load_filter_pipeline": server_load_pipeline,
        "client_manager": client_mgr,
    }


def create_server(config: Config) -> FastMCP:
    """Create a configured FastMCP proxy server for the given config."""

    @lifespan
    async def configured_lifespan(server: FastMCP):
        ctx = await _setup(config)
        yield ctx
        logger.info("Shutting down, closing connections...")
        await ctx["client_manager"].close_all()

    server = FastMCP(
        name="extensible-mcp",
        instructions=(
            "This server provides semantic search over tools from multiple MCP servers. "
            "Use `search_tools` to find relevant tools by describing what you want to do, "
            "then use `call_tool` to invoke the selected tool."
        ),
        lifespan=configured_lifespan,
    )

    @server.tool(
        name="search_tools",
        description=(
            "Search for available tools by describing what you want to do. "
            "Returns matching tool definitions with their names, descriptions, "
            "and parameter schemas. Use the tool name from results with `call_tool` to invoke."
        ),
    )
    async def search_tools_handler(query: str, ctx: Context, top_k: int = 5) -> str:
        vs: VectorStore = ctx.lifespan_context["vector_store"]
        pipeline: FilterPipeline = ctx.lifespan_context["filter_pipeline"]
        results = vs.search(query, top_k=top_k)
        results = pipeline.apply(results, query)
        return _format_search_results(results)

    @server.tool(
        name="call_tool",
        description=(
            "Call a tool on a downstream MCP server. "
            "Use the qualified tool name (e.g. 'github__create_issue') from search_tools results. "
            "Pass the arguments as a JSON object matching the tool's parameter schema."
        ),
    )
    async def call_tool_handler(
        tool_name: str, arguments: dict[str, Any], ctx: Context
    ) -> str:
        call_pipeline: CallFilterPipeline = ctx.lifespan_context["call_filter_pipeline"]
        client_mgr: ClientManager = ctx.lifespan_context["client_manager"]

        parts = tool_name.split("__", 1)
        server_name = parts[0] if len(parts) == 2 else ""

        request = CallRequest(
            tool_name=tool_name, arguments=arguments, server_name=server_name
        )
        filter_result = await call_pipeline.apply(request)
        if not filter_result.allowed:
            return f"Error: {filter_result.reason}"

        tool_name = filter_result.tool_name
        arguments = filter_result.arguments

        if tool_name not in client_mgr.get_qualified_names():
            return f"Error: Unknown tool '{tool_name}'. Use search_tools to find available tools."

        try:
            result: mcp_types.CallToolResult = await client_mgr.call_tool(
                tool_name, arguments
            )
        except Exception as e:
            return f"Error calling tool '{tool_name}': {e}"

        if result.isError:
            texts = [
                block.text
                for block in result.content
                if isinstance(block, mcp_types.TextContent)
            ]
            return f"Tool error: {' '.join(texts)}"

        output_parts: list[str] = []
        for block in result.content:
            if isinstance(block, mcp_types.TextContent):
                output_parts.append(block.text)
            else:
                output_parts.append(f"[{type(block).__name__}]")
        return "\n".join(output_parts) if output_parts else "(no output)"

    @server.tool(
        name="load_mcp_server",
        description=(
            "Dynamically connect to a new remote MCP server by URL. "
            "Indexes all of the server's tools and makes them available for "
            "search_tools and call_tool. The server_name is used as a namespace "
            "prefix for tool names (e.g. 'myserver__tool_name')."
        ),
    )
    async def load_mcp_server_handler(
        server_name: str, url: str, ctx: Context
    ) -> str:
        server_load_pipeline: ServerLoadFilterPipeline = ctx.lifespan_context[
            "server_load_filter_pipeline"
        ]
        vs: VectorStore = ctx.lifespan_context["vector_store"]
        client_mgr: ClientManager = ctx.lifespan_context["client_manager"]

        load_request = ServerLoadRequest(server_name=server_name, url=url)
        load_result = await server_load_pipeline.apply(load_request)
        if not load_result.allowed:
            return f"Error: {load_result.reason}"

        if server_name in client_mgr._connections:
            return f"Error: Server '{server_name}' is already connected."

        try:
            tools = await client_mgr.connect_url(server_name, url)
        except Exception as e:
            return f"Error connecting to '{url}': {e}"

        vs.add(tools)
        return (
            f"Successfully connected to '{server_name}' at {url}. "
            f"Indexed {len(tools)} tool(s). They are now available via search_tools and call_tool."
        )

    return server


def main() -> None:
    args = _parse_args()
    config_path = find_config_path(args.config)
    logger.info("Loading config from %s", config_path)
    config = load_config(config_path)
    server = create_server(config)
    server.run()

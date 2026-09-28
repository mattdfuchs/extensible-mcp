# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from fastmcp import FastMCP, Context
from fastmcp.server.lifespan import lifespan
import mcp.types as mcp_types

from . import admin
from .client_manager import ClientManager, TokenExpiredError
from .config import Config, find_config_path, load_config
from .filters import (
    AccessControlFilter,
    CallFilter,
    CallFilterPipeline,
    DiscoveredToolsFilter,
    FilterPipeline,
    RegoPolicyFilter,
    ResponseFilter,
    ResponseFilterPipeline,
    ServerLoadAccessControlFilter,
    ServerLoadFilter,
    ServerLoadFilterPipeline,
    SimilarityThresholdFilter,
    ToolFilter,
)
from .routing import BundleRouter
from .types import CallRequest, CallResponse, LocalTool, ServerLoadRequest, ToolRecord
from .vector_store import VectorStore

logger = logging.getLogger(__name__)


def _install_reload_handler(
    ctx: dict[str, Any], reload_config: Callable[[], Config] | None
) -> Callable[[], None]:
    """Reload the server list on SIGHUP, if the embedder asked for it.

    Installed from inside the lifespan because that is the only place holding
    the live ``ClientManager`` and ``VectorStore``; opt-in because a library
    must not claim a process-wide signal on its own. The CLI passes
    ``reload_config``; an embedded proxy passes nothing and nothing changes.

    The handler only schedules the work: a signal handler runs between
    bytecodes, so anything awaited there would run outside the loop's control.
    """
    if reload_config is None or not hasattr(signal, "SIGHUP"):
        return lambda: None

    loop = asyncio.get_running_loop()

    async def _reload() -> None:
        try:
            config = reload_config()
        except Exception:
            logger.warning("Reload: config could not be read; ignoring", exc_info=True)
            return
        added, refused = await reconcile_servers(ctx, config)
        if added:
            logger.info("Reload: added %s", ", ".join(added))
        if refused:
            logger.warning("Reload: refused or unreachable: %s", ", ".join(refused))
        if not added and not refused:
            logger.info("Reload: nothing new in the config")

    def _on_sighup() -> None:
        loop.create_task(_reload())

    loop.add_signal_handler(signal.SIGHUP, _on_sighup)
    logger.info("Reload on SIGHUP is armed (pid %d)", os.getpid())

    def remove() -> None:
        loop.remove_signal_handler(signal.SIGHUP)

    return remove


async def reconcile_servers(
    ctx: dict[str, Any], config: Config
) -> tuple[list[str], list[str]]:
    """Connect and index servers in ``config`` that are not connected yet.

    Additive only. A server that has disappeared from the config stays
    connected, and one whose URL changed keeps the URL it was admitted with --
    disconnecting under a signal would cancel calls in flight, and silently
    re-pointing a name at a new host is exactly the substitution the token
    binding exists to prevent. Both are deliberate; removal is an operator
    action, which means a restart.

    A changed *token* needs nothing: a URL server resolves the tokens file per
    call, so the next call already uses the new value.

    Returns ``(added, refused)``.
    """
    client_mgr: ClientManager = ctx["client_manager"]
    vs: VectorStore = ctx["vector_store"]
    router: BundleRouter | None = ctx.get("bundle_router")

    # The tokens file usually does not exist when the proxy starts -- creating
    # it is what `add-server` does -- so the manager has to be told where it is
    # now, or the server it just wrote a token for connects without one.
    client_mgr.set_tokens_file(config.tokens_file)

    known = client_mgr.server_names()
    wanted = [sc for sc in config.servers if sc.name not in known]
    if router is not None:
        wanted = _admit_servers(router, wanted)
    refused = [sc.name for sc in config.servers
               if sc.name not in known and sc.name not in {w.name for w in wanted}]

    added: list[str] = []
    for server_config in wanted:
        try:
            records = await client_mgr.connect_configured(server_config)
        except Exception:
            logger.warning(
                "Reload: could not connect '%s', leaving it out",
                server_config.name, exc_info=True,
            )
            refused.append(server_config.name)
            continue
        vs.add(records)
        added.append(server_config.name)
    return added, refused


def _describe(exc: BaseException) -> str:
    """A message worth showing the LLM.

    anyio task groups wrap the real failure, so a downstream that refused a
    connection arrived as "unhandled errors in a TaskGroup (1 sub-exception)"
    -- true, and useless to a model deciding what to do next. Unwrap to the
    leaves and name them.
    """
    if isinstance(exc, BaseExceptionGroup):
        leaves = [_describe(e) for e in exc.exceptions]
        inner = "; ".join(d for d in leaves if d)
        return inner or str(exc)
    text = str(exc).strip()
    return text or type(exc).__name__


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extensible MCP Proxy")
    parser.add_argument("--config", type=str, default=None, help="Path to config file")
    sub = parser.add_subparsers(dest="command")

    add = sub.add_parser(
        "add-server",
        help="Verify an authenticated MCP server, record it, and reload a running proxy",
        description=(
            "Connect to URL as an MCP client using TOKEN, and only if that "
            "works write the server into the config file and the token into "
            "the tokens file, then SIGHUP a proxy running against that config "
            "so it indexes the new tools without a restart. The token is never "
            "seen by the model: this is an operator command, not an MCP tool."
        ),
    )
    add.add_argument("--name", required=True, help="Server name, the tool namespace prefix")
    add.add_argument("--url", required=True, help="Streamable HTTP MCP endpoint")
    add.add_argument(
        "--token",
        help="Bearer token. Omit for an unauthenticated server; use --token-stdin to pipe it.",
    )
    add.add_argument(
        "--token-stdin",
        action="store_true",
        help="Read the token from stdin, keeping it out of the shell history and process list",
    )
    add.add_argument("--config", type=str, default=None, help="Path to config file")
    return parser.parse_args(argv)


def _build_pipelines(
    config: Config,
    *,
    extra_search_filters: Sequence[ToolFilter] = (),
    extra_call_filters: Sequence[CallFilter] = (),
    extra_response_filters: Sequence[ResponseFilter] = (),
    extra_load_filters: Sequence[ServerLoadFilter] = (),
    bundle_router: BundleRouter | None = None,
) -> tuple[
    FilterPipeline,
    CallFilterPipeline,
    ResponseFilterPipeline,
    ServerLoadFilterPipeline,
    DiscoveredToolsFilter,
]:
    ac = AccessControlFilter(
        deny=config.filters.access_control.deny,
        deny_patterns=config.filters.access_control.deny_patterns,
        allow_servers=config.filters.access_control.allow_servers or None,
    )

    search_pipeline = FilterPipeline([
        SimilarityThresholdFilter(config.filters.similarity_threshold),
        ac,
    ])
    for f in extra_search_filters:
        search_pipeline.add(f)

    discovered_filter = DiscoveredToolsFilter()
    call_pipeline = CallFilterPipeline([ac, discovered_filter])

    if config.filters.rego_policy:
        call_pipeline.add(RegoPolicyFilter(config.filters.rego_policy))

    for f in extra_call_filters:
        call_pipeline.add(f)

    # The per-server bundle router runs last: after access control, the
    # discovered-tools guarantee, and any custom filters. It dispatches each
    # call to the policy bundle selected for that call's server (pass-through
    # for ungoverned servers).
    if bundle_router is not None:
        call_pipeline.add(bundle_router)

    response_pipeline = ResponseFilterPipeline()
    for f in extra_response_filters:
        response_pipeline.add(f)

    lc = config.filters.load_control
    server_load_pipeline = ServerLoadFilterPipeline()
    if lc.deny_names or lc.deny_name_patterns or lc.deny_url_patterns or lc.allow_url_patterns:
        server_load_pipeline.add(ServerLoadAccessControlFilter(
            deny_names=lc.deny_names,
            deny_name_patterns=lc.deny_name_patterns,
            deny_url_patterns=lc.deny_url_patterns,
            allow_url_patterns=lc.allow_url_patterns,
        ))

    for f in extra_load_filters:
        server_load_pipeline.add(f)

    return (
        search_pipeline,
        call_pipeline,
        response_pipeline,
        server_load_pipeline,
        discovered_filter,
    )


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


def _build_local_registry(local_tools: Sequence[LocalTool]) -> dict[str, LocalTool]:
    registry: dict[str, LocalTool] = {}
    for lt in local_tools:
        if lt.name in registry:
            raise ValueError(f"Duplicate local tool name: {lt.name!r}")
        registry[lt.name] = lt
    return registry


async def _setup(
    config: Config,
    *,
    extra_search_filters: Sequence[ToolFilter] = (),
    extra_call_filters: Sequence[CallFilter] = (),
    extra_response_filters: Sequence[ResponseFilter] = (),
    extra_load_filters: Sequence[ServerLoadFilter] = (),
    bundle_router: BundleRouter | None = None,
    local_tools: Sequence[LocalTool] = (),
) -> dict[str, Any]:
    """Connect to downstream servers, build vector index, return lifespan context."""
    (
        search_pipeline,
        call_pipeline,
        response_pipeline,
        server_load_pipeline,
        discovered_filter,
    ) = _build_pipelines(
        config,
        extra_search_filters=extra_search_filters,
        extra_call_filters=extra_call_filters,
        extra_response_filters=extra_response_filters,
        extra_load_filters=extra_load_filters,
        bundle_router=bundle_router,
    )

    client_mgr = ClientManager(tokens_file=config.tokens_file)
    logger.info(
        "Tokens file: %s",
        config.tokens_file if config.tokens_file else "(none configured)",
    )

    servers = config.servers
    if bundle_router is not None:
        servers = _admit_servers(bundle_router, config.servers)

    logger.info("Connecting to %d downstream server(s)...", len(servers))
    tools = await client_mgr.connect_all(servers)
    logger.info("Indexed %d tools total", len(tools))

    local_registry = _build_local_registry(local_tools)
    local_records = [
        ToolRecord(
            name=lt.name,
            qualified_name=lt.name,
            description=lt.description,
            input_schema=lt.input_schema,
            server_name="",
        )
        for lt in local_tools
    ]
    if local_records:
        logger.info("Indexed %d local tool(s)", len(local_records))

    vector_store = VectorStore()
    logger.info("Building vector index...")
    vector_store.index(tools + local_records)
    logger.info("Vector index ready")

    return {
        "vector_store": vector_store,
        "filter_pipeline": search_pipeline,
        "call_filter_pipeline": call_pipeline,
        "response_filter_pipeline": response_pipeline,
        "server_load_filter_pipeline": server_load_pipeline,
        "client_manager": client_mgr,
        "discovered_filter": discovered_filter,
        "bundle_router": bundle_router,
        "local_tools": local_registry,
    }


def _admit_servers(router: BundleRouter, servers):
    """Run stage-one selection over the static servers, returning those the
    router admits. A refused server is logged and not connected."""
    admitted = []
    for s in servers:
        decision = router.admit(
            server_name=s.name,
            url=s.url,
            how_loaded="static",
            transport="http" if s.url else "stdio",
        )
        if decision.allowed:
            logger.info(
                "Server %r admitted to bundle %r (via %s)",
                s.name,
                decision.bundle,
                decision.source,
            )
            admitted.append(s)
        else:
            logger.warning(
                "Server %r refused at load: %s (via %s)",
                s.name,
                decision.reason,
                decision.source,
            )
    return admitted


def create_server(
    config: Config,
    *,
    extra_search_filters: Sequence[ToolFilter] = (),
    extra_call_filters: Sequence[CallFilter] = (),
    extra_response_filters: Sequence[ResponseFilter] = (),
    extra_load_filters: Sequence[ServerLoadFilter] = (),
    bundle_router: BundleRouter | None = None,
    local_tools: Sequence[LocalTool] = (),
    reload_config: Callable[[], Config] | None = None,
) -> FastMCP:
    """Create a configured FastMCP proxy server for the given config.

    The ``extra_*_filters`` arguments accept user-defined filters (anything
    matching the ``ToolFilter``, ``CallFilter``, ``ResponseFilter``, or
    ``ServerLoadFilter`` Protocol). They are appended to the corresponding
    pipeline after the built-in reference filters; the discovered-tools
    guarantee is always enforced regardless.

    ``bundle_router`` opts into per-server policy bundles: when present, each
    server is run through stage-one selection at load (refused servers do not
    connect), and each call is routed to the policy bundle selected for its
    server. When absent, behaviour is unchanged.

    ``local_tools`` registers in-process tools (embedder-supplied Python
    callables, not a downstream MCP server) that are discovered via
    ``search_tools`` and invoked via ``call_tool`` exactly like a downstream
    tool — the same ``CallFilterPipeline`` (access control, discovered-tools
    guarantee, policy filters) runs on them too. There is no separate,
    unfiltered way to register a tool directly on the returned server that
    bypasses this — that asymmetry between "local" and "downstream" tools is
    exactly what ``local_tools`` exists to remove.
    """

    @lifespan
    async def configured_lifespan(server: FastMCP):
        ctx = await _setup(
            config,
            extra_search_filters=extra_search_filters,
            extra_call_filters=extra_call_filters,
            extra_response_filters=extra_response_filters,
            extra_load_filters=extra_load_filters,
            bundle_router=bundle_router,
            local_tools=local_tools,
        )
        remove_handler = _install_reload_handler(ctx, reload_config)
        try:
            yield ctx
        finally:
            remove_handler()
            logger.info("Shutting down, closing connections...")
            await ctx["client_manager"].close_all()

    server = FastMCP(
        name="extensible-mcp",
        instructions=(
            "This server is a proxy to other MCP tool servers. "
            "You do not have direct tool definitions — discover them on demand.\n\n"
            "Workflow:\n"
            "1. Use `search_tools` with a natural language query to find relevant tools.\n"
            "2. Use `call_tool` with the qualified name from search results "
            "(e.g. 'github__create_issue') and arguments matching the returned schema.\n"
            "3. You may only call tools you have previously discovered via search_tools.\n\n"
            "Dynamic servers:\n"
            "- Use `load_mcp_server` to connect to a new remote MCP server by URL.\n"
            "- If the server requires authentication, ask the user to add a token "
            "for that server name to the tokens file AND add the server to "
            "the config file, since a stored token is only ever sent to a URL "
            "named in the config.\n\n"
            "Authentication errors:\n"
            "- If a call_tool fails with an authentication/token error, ask the user "
            "to update the token in the tokens file, then retry the same call.\n"
            "- Never ask the user to provide tokens in the conversation. "
            "Tokens are managed through the tokens file only."
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
        discovered_filter: DiscoveredToolsFilter = ctx.lifespan_context["discovered_filter"]
        results = vs.search(query, top_k=top_k)
        results = pipeline.apply(results, query)
        # Registered against this session, so what one conversation surfaced
        # does not become callable by another.
        discovered_filter.register(
            [r.tool.qualified_name for r in results], ctx.session_id
        )
        return _format_search_results(results)

    @server.tool(
        name="call_tool",
        description=(
            "Call a tool — either on a downstream MCP server or one of the "
            "proxy's own local tools. Use the tool name from search_tools "
            "results verbatim: a downstream tool's name is qualified "
            "(e.g. 'github__create_issue'), a local tool's is not. "
            "Pass the arguments as a JSON object matching the tool's parameter schema."
        ),
    )
    async def call_tool_handler(
        tool_name: str, arguments: dict[str, Any], ctx: Context
    ) -> str:
        call_pipeline: CallFilterPipeline = ctx.lifespan_context["call_filter_pipeline"]
        response_pipeline: ResponseFilterPipeline = ctx.lifespan_context[
            "response_filter_pipeline"
        ]
        client_mgr: ClientManager = ctx.lifespan_context["client_manager"]
        local_tools: dict[str, LocalTool] = ctx.lifespan_context["local_tools"]

        parts = tool_name.split("__", 1)
        server_name = parts[0] if len(parts) == 2 else ""

        request = CallRequest(
            tool_name=tool_name,
            arguments=arguments,
            server_name=server_name,
            session_id=ctx.session_id,
        )
        filter_result = await call_pipeline.apply(request)
        if not filter_result.allowed:
            return f"Error: {filter_result.reason}"

        tool_name = filter_result.tool_name
        arguments = filter_result.arguments

        if tool_name in local_tools:
            try:
                raw_result = await local_tools[tool_name].handler(arguments)
            except Exception as e:
                return f"Error calling tool '{tool_name}': {_describe(e)}"
            text = raw_result if isinstance(raw_result, str) else json.dumps(raw_result)
            content: list[Any] = [mcp_types.TextContent(type="text", text=text)]
            is_error = False
        elif tool_name in client_mgr.get_qualified_names():
            try:
                result: mcp_types.CallToolResult = await client_mgr.call_tool(
                    tool_name, arguments
                )
            except TokenExpiredError as e:
                return (
                    f"Error: Authentication failed for server '{e.server_name}' "
                    f"(token unchanged for {e.token_age_minutes} minutes). "
                    f"The token may have expired. Ask the user to update the token "
                    f"for '{e.server_name}' in the tokens file, then retry the call."
                )
            except Exception as e:
                return f"Error calling tool '{tool_name}': {_describe(e)}"
            content = list(result.content)
            is_error = result.isError
        else:
            return f"Error: Unknown tool '{tool_name}'. Use search_tools to find available tools."

        response_request = CallResponse(
            tool_name=tool_name,
            arguments=arguments,
            server_name=server_name,
            content=content,
            is_error=is_error,
        )
        response_result = await response_pipeline.apply(response_request)
        if not response_result.allowed:
            return f"Error: {response_result.reason}"

        content = response_result.content
        is_error = response_result.is_error

        if is_error:
            texts = [
                block.text
                for block in content
                if isinstance(block, mcp_types.TextContent)
            ]
            return f"Tool error: {' '.join(texts)}"

        output_parts: list[str] = []
        for block in content:
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
            "prefix for tool names (e.g. 'myserver__tool_name'). "
            "A server loaded this way is not sent any stored credential: a "
            "token is presented only to a URL an operator named in the config "
            "file. If the server needs authentication, ask the user to add it "
            "to the config rather than loading it here."
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

        if "__" in server_name:
            return (
                f"Error: Server name '{server_name}' must not contain '__'. That "
                "separator is reserved for qualified tool names; a server named "
                "with it would be routed as a different server."
            )

        load_request = ServerLoadRequest(server_name=server_name, url=url)
        load_result = await server_load_pipeline.apply(load_request)
        if not load_result.allowed:
            return f"Error: {load_result.reason}"

        if server_name in client_mgr._connections:
            return f"Error: Server '{server_name}' is already connected."

        router: BundleRouter | None = ctx.lifespan_context.get("bundle_router")
        if router is not None:
            decision = router.admit(
                server_name=server_name,
                url=url,
                how_loaded="runtime",
                transport="http",
            )
            if not decision.allowed:
                return (
                    f"Error: Server '{server_name}' refused by policy: "
                    f"{decision.reason}"
                )

        try:
            tools = await client_mgr.connect_url(server_name, url)
        except Exception as e:
            return f"Error connecting to '{url}': {_describe(e)}"

        logger.info("Indexing %d tools from '%s'...", len(tools), server_name)
        vs.add(tools)
        logger.info("Indexing complete for '%s'", server_name)
        return (
            f"Successfully connected to '{server_name}' at {url}. "
            f"Indexed {len(tools)} tool(s). They are now available via search_tools and call_tool."
        )

    return server


def _add_server_command(args: argparse.Namespace) -> int:
    """`extensible-mcp add-server`: verify, record, reload."""
    config_path = find_config_path(args.config)
    token = args.token
    if args.token_stdin:
        token = sys.stdin.read().strip()
    if args.token and args.token_stdin:
        print("Pass --token or --token-stdin, not both.", file=sys.stderr)
        return 2

    try:
        verified = asyncio.run(admin.verify_server(args.name, args.url, token))
    except admin.AdminError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        admin.add_server_to_config(config_path, args.name, args.url)
    except admin.AdminError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if token:
        tokens_path = load_config(config_path).tokens_file or config_path.parent / "tokens"
        admin.write_token(tokens_path, args.name, token)
        print(f"Token for '{args.name}' written to {tokens_path} (0600).")

    print(
        f"Verified {args.url}: {len(verified.tool_names)} tool(s) "
        f"({', '.join(verified.tool_names[:5])}"
        f"{', …' if len(verified.tool_names) > 5 else ''})."
    )
    print(f"Added '{args.name}' to {config_path}.")

    pid = admin.signal_reload(config_path)
    if pid is None:
        print("No running proxy found for this config; it will pick this up at next start.")
    else:
        print(f"Signalled the proxy (pid {pid}) to reload.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    # Only the CLI owns the root logger. Doing this at import time
    # reconfigured logging for any application that embedded the proxy.
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    args = _parse_args(argv)
    if args.command == "add-server":
        return _add_server_command(args)

    config_path = find_config_path(args.config)
    logger.info("Loading config from %s", config_path)
    config = load_config(config_path)
    # reload_config is what arms SIGHUP. The CLI supplies it -- and with it the
    # policy that "the config" means this file -- while the lifespan supplies
    # the machinery, since only it holds the live manager and index.
    server = create_server(config, reload_config=lambda: load_config(config_path))
    try:
        pid_file = admin.write_pid_file(config_path)
    except admin.AdminError as e:
        # Two proxies on one config would race on the same downstreams, and
        # leave add-server signalling whichever wrote the file last.
        print(f"error: {e}", file=sys.stderr)
        return 1
    try:
        server.run()
    finally:
        admin.remove_pid_file(pid_file)
    return 0

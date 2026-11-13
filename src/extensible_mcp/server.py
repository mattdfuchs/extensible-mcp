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
from fastmcp.exceptions import ToolError
from fastmcp.server.lifespan import lifespan
from fastmcp.server.middleware import Middleware
from fastmcp.tools import Tool, ToolResult
import mcp.types as mcp_types

from . import admin
from .client_manager import ClientManager, TokenExpiredError
from .config import Config, find_config_path, load_config
from .declared_bundles import build_declared_bundle_filters
from .principal import (
    PrincipalError,
    PrincipalMapping,
    build_auth_provider,
    principal_from_token,
)
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
    StaticCatalogueFilter,
    ToolFilter,
)
from .routing import BundleRouter
from .types import (
    CallRequest,
    CallResponse,
    LocalTool,
    Principal,
    SearchResult,
    ServerLoadRequest,
    ToolRecord,
)
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
    # A reload can add a server naming a credential the manager has not seen.
    client_mgr.set_credentials(config.credentials)

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


LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

_HTTP_CONSTRAINT = (
    "--transport http serves many callers from one process, so it refuses to "
    "start unless the config carries an 'auth' block (issuer, audience, and the "
    "issuer's keys) or --allow-anonymous says this is one person's proxy on "
    "loopback. It also refuses a configured tokens file, which presents one "
    "credential for every caller, and it does not offer load_mcp_server: on a "
    "shared proxy servers are configured, not loaded."
)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extensible MCP Proxy",
        epilog=_HTTP_CONSTRAINT,
    )
    parser.add_argument("--config", type=str, default=None, help="Path to config file")
    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default="stdio",
        help=(
            "stdio (the default) serves the one client that launched the process; "
            "http listens on --host:--port for many and requires inbound auth "
            "(see below)"
        ),
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="Address to listen on with --transport http"
    )
    parser.add_argument("--port", type=int, default=8000, help="Port for --transport http")
    parser.add_argument(
        "--allow-anonymous",
        action="store_true",
        help=(
            "Serve HTTP with no inbound auth: single tenant on purpose, one "
            "person's proxy on a loopback --host. Refused with an 'auth' block "
            "or a non-loopback host."
        ),
    )
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


class TransportError(ValueError):
    """A deployment the CLI refuses to start: not a warning, an exit."""


def check_http_deployment(
    config: Config, *, allow_anonymous: bool = False, host: str = "127.0.0.1"
) -> bool:
    """The gate on ``--transport http``: what it refuses, and the
    ``require_principal`` it settles on when it does not.

    A stdio proxy is launched by the one client it serves, so the process
    boundary is the principal boundary and nothing about identity needs
    saying. An HTTP listener serves whoever reaches the port, and three
    things that were sound by that coincidence stop being sound:

    - **No inbound auth.** Every principal would be ``None``, every
      per-principal control (catalogue scoping, the discovered-tools set,
      the ``caller`` source) would key on the process, and the proxy would
      show one caller another's tools. Refused unless the operator says
      ``--allow-anonymous``: single tenant on purpose, on a loopback host,
      with no ``auth`` block to contradict it.
    - **A tokens file.** One bearer per downstream server, per process, is one
      downstream identity for every caller: the confused deputy, and a filter
      bug would act with the credential's full authority. Refused flat, since
      an HTTP listener cannot show it serves one person. Per-principal
      downstream credentials are a later release.
    - **The ``auth`` block itself is checked at load**: ``issuer`` and
      ``audience`` are both required there, so a verifier that accepts any
      issuer's token for any audience is not expressible in the config.

    Returns the ``require_principal`` to pass to :func:`create_server`:
    ``True`` with auth, ``False`` for the anonymous case. Raises
    :class:`TransportError` naming what was refused.
    """
    if config.tokens_file is not None:
        raise TransportError(
            f"--transport http refuses a configured tokens file ({config.tokens_file}): "
            "the file holds one credential per downstream server for the whole "
            "process, which an HTTP proxy would present on behalf of every caller. "
            "Remove the file (or EXTENSIBLE_MCP_TOKENS_FILE) and use a "
            "'credentials' entry, or serve this config over stdio. The tokens "
            "file is stdio-only."
        )
    if allow_anonymous:
        if config.auth is not None:
            raise TransportError(
                "--allow-anonymous with an 'auth' block says two things: pick one. "
                "Drop the flag to require the configured verifier's principal on "
                "every request, or drop the block to serve one person on loopback."
            )
        if host not in LOOPBACK_HOSTS:
            raise TransportError(
                f"--allow-anonymous listens on {host!r}, which is not loopback. An "
                "anonymous proxy is one person's, and a reachable port is not one "
                f"person's; bind one of {sorted(LOOPBACK_HOSTS)} or configure 'auth'."
            )
        return False
    if config.auth is None:
        raise TransportError(
            "--transport http needs an 'auth' block (issuer, audience, and "
            "jwks_uri or public_key_file): one process serves many callers, and "
            "without a verified principal it cannot tell them apart. For one "
            "person's proxy on loopback, say so with --allow-anonymous."
        )
    return True


def _over_http() -> bool:
    """Whether the current request arrived over HTTP. A runtime fact rather
    than a configuration one, so it holds however the server was run."""
    from fastmcp.server.dependencies import get_http_request

    try:
        get_http_request()
    except RuntimeError:
        return False
    return True


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
    DiscoveredToolsFilter | StaticCatalogueFilter,
]:
    ac = AccessControlFilter(
        deny=config.filters.access_control.deny,
        deny_patterns=config.filters.access_control.deny_patterns,
        allow_servers=config.filters.access_control.allow_servers or None,
        by_role=config.filters.access_control.by_role,
    )

    search_pipeline = FilterPipeline([
        SimilarityThresholdFilter(config.filters.similarity_threshold),
        ac,
    ])
    for f in extra_search_filters:
        search_pipeline.add(f)

    # The one structurally enforced rule, in the shape the exposure needs:
    # recorded at search under dynamic exposure, derived from the view under
    # static. Either way it is in the pipeline unconditionally.
    discovered_filter: DiscoveredToolsFilter | StaticCatalogueFilter
    if config.exposure == "static":
        discovered_filter = StaticCatalogueFilter()
    else:
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
    by_role = config.filters.access_control.by_role
    server_load_pipeline = ServerLoadFilterPipeline()
    if (
        lc.deny_names or lc.deny_name_patterns or lc.deny_url_patterns
        or lc.allow_url_patterns or by_role is not None
    ):
        server_load_pipeline.add(ServerLoadAccessControlFilter(
            deny_names=lc.deny_names,
            deny_name_patterns=lc.deny_name_patterns,
            deny_url_patterns=lc.deny_url_patterns,
            allow_url_patterns=lc.allow_url_patterns,
            by_role=by_role,
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


def _catalogue_view(
    vector_store: VectorStore, search_pipeline: FilterPipeline, principal: Principal | None
) -> list[SearchResult]:
    """The catalogue as ``principal`` may see it: every indexed record, run
    through the search pipeline exactly as a search result would be, with
    the empty query and a score of ``1.0``. One rule decides what a person
    sees, whether they searched or were listed: access control and role
    scoping (fail-closed under ``by_role``), the bundle augmenter, and every
    custom search filter, which can tell a listing from a search by the
    empty query."""
    results = [SearchResult(tool=record, score=1.0) for record in vector_store.records()]
    return search_pipeline.apply(results, "", principal=principal)


class _Refused(Exception):
    """A call the proxy did not dispatch, with the reason rendered for the
    model. ``text`` is the ``call_tool`` meta-tool's rendering of it, kept
    byte-for-byte what it was before static exposure existed."""

    def __init__(self, reason: str, text: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.text = text if text is not None else f"Error: {reason}"


async def _dispatch_call(
    ctx: Context, tool_name: str, arguments: dict[str, Any]
) -> tuple[list[Any], bool, Any]:
    """The one call path. Both entry points -- the ``call_tool`` meta-tool
    and a tool called by its listed name under static exposure -- run this
    and nothing else: the principal, the call pipeline (access control, the
    discovered-tools or catalogue rule, policy filters, the bundle router),
    local or downstream dispatch, then the response pipeline. Returns the
    native result (content blocks, ``is_error``, structured content) for the
    caller to render; raises :class:`_Refused` when nothing was dispatched.
    """
    call_pipeline: CallFilterPipeline = ctx.lifespan_context["call_filter_pipeline"]
    response_pipeline: ResponseFilterPipeline = ctx.lifespan_context[
        "response_filter_pipeline"
    ]
    client_mgr: ClientManager = ctx.lifespan_context["client_manager"]
    local_tools: dict[str, LocalTool] = ctx.lifespan_context["local_tools"]

    parts = tool_name.split("__", 1)
    server_name = parts[0] if len(parts) == 2 else ""
    try:
        principal = _current_principal(ctx)
    except PrincipalError as e:
        raise _Refused(str(e))

    request = CallRequest(
        tool_name=tool_name,
        arguments=arguments,
        server_name=server_name,
        session_id=ctx.session_id,
        principal=principal,
    )
    filter_result = await call_pipeline.apply(request)
    if not filter_result.allowed:
        raise _Refused(filter_result.reason)

    tool_name = filter_result.tool_name
    arguments = filter_result.arguments

    if tool_name in local_tools:
        try:
            raw_result = await local_tools[tool_name].handler(arguments)
        except Exception as e:
            raise _Refused(
                f"calling tool '{tool_name}': {_describe(e)}",
                f"Error calling tool '{tool_name}': {_describe(e)}",
            )
        text = raw_result if isinstance(raw_result, str) else json.dumps(raw_result)
        content: list[Any] = [mcp_types.TextContent(type="text", text=text)]
        is_error = False
        structured_content = raw_result if isinstance(raw_result, dict) else None
    elif tool_name in client_mgr.get_qualified_names():
        try:
            result: mcp_types.CallToolResult = await client_mgr.call_tool(
                tool_name, arguments
            )
        except TokenExpiredError as e:
            raise _Refused(
                f"Authentication failed for server '{e.server_name}' "
                f"(token unchanged for {e.token_age_minutes} minutes). "
                f"The token may have expired. Ask the user to fix the credential "
                f"configured for '{e.server_name}', then retry the call."
            )
        except Exception as e:
            raise _Refused(
                f"calling tool '{tool_name}': {_describe(e)}",
                f"Error calling tool '{tool_name}': {_describe(e)}",
            )
        content = list(result.content)
        is_error = result.is_error
        structured_content = result.structured_content
    else:
        raise _Refused(
            f"Unknown tool '{tool_name}'. Use search_tools to find available tools."
        )

    response_request = CallResponse(
        tool_name=tool_name,
        arguments=arguments,
        server_name=server_name,
        content=content,
        is_error=is_error,
        structured_content=structured_content,
        principal=principal,
    )
    response_result = await response_pipeline.apply(response_request)
    if not response_result.allowed:
        raise _Refused(response_result.reason)
    return response_result.content, response_result.is_error, structured_content


class StaticExposure(Middleware):
    """Static exposure: ``tools/list`` answers with the caller's view of the
    governed catalogue, and every listed name dispatches through
    :func:`_dispatch_call`.

    Nothing is registered on the ``FastMCP`` object -- the registry under
    this middleware still holds only the proxy's own tools, which is what
    keeps a listed tool subject to every filter. The three meta-tools are
    not listed and not reachable by name in this mode: static means static,
    with no discovery workflow and no runtime loading.

    The listing is a menu, not an allowance. The proxy learns who is calling
    from the token on each request and checks the call against that
    caller's view, whoever listed and whenever; a platform that listed
    under one identity and calls under another gets the caller's answer.
    """

    async def on_list_tools(self, context, call_next):
        ctx = context.fastmcp_context
        try:
            principal = _current_principal(ctx)
        except PrincipalError as e:
            raise ToolError(str(e))
        view = _catalogue_view(
            ctx.lifespan_context["vector_store"], ctx.lifespan_context["filter_pipeline"], principal
        )
        return [
            Tool(
                name=r.tool.qualified_name,
                description=r.tool.description,
                parameters=r.tool.input_schema,
            )
            for r in view
        ]

    async def on_call_tool(self, context, call_next):
        ctx = context.fastmcp_context
        name = context.message.name
        arguments = dict(context.message.arguments or {})
        try:
            content, is_error, structured_content = await _dispatch_call(ctx, name, arguments)
        except _Refused as e:
            # A tool-level error, which the model sees and can act on; a
            # JSON-RPC error would surface in the platform as an exception.
            raise ToolError(e.reason)
        return ToolResult(
            content=content,
            structured_content=structured_content if isinstance(structured_content, dict) else None,
            is_error=is_error,
        )


async def _setup(
    config: Config,
    *,
    extra_search_filters: Sequence[ToolFilter] = (),
    extra_call_filters: Sequence[CallFilter] = (),
    extra_response_filters: Sequence[ResponseFilter] = (),
    extra_load_filters: Sequence[ServerLoadFilter] = (),
    bundle_router: BundleRouter | None = None,
    local_tools: Sequence[LocalTool] = (),
    principal_mapping: PrincipalMapping | None = None,
    require_principal: bool | None = None,
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

    client_mgr = ClientManager(
        tokens_file=config.tokens_file, credentials=config.credentials
    )
    logger.info(
        "Tokens file: %s",
        config.tokens_file if config.tokens_file else "(none configured)",
    )
    logger.info(
        "Credentials: %s",
        ", ".join(
            f"{name} ({cred.grant})" for name, cred in sorted(config.credentials.items())
        )
        or "(none configured)",
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

    if isinstance(discovered_filter, StaticCatalogueFilter):
        discovered_filter.bind(
            lambda principal: {
                r.tool.qualified_name
                for r in _catalogue_view(vector_store, search_pipeline, principal)
            }
        )

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
        "principal_mapping": principal_mapping,
        "require_principal": bool(require_principal),
    }


def _current_principal(ctx: Context) -> Principal | None:
    """The principal behind this request, from the token FastMCP verified on
    it. Read per request, never cached per session: on Streamable HTTP the
    bearer travels on every message and FastMCP verifies each one.

    Raises :class:`PrincipalError`, which the handler returns as an error,
    when the deployment requires a principal and the request carries none.
    Enforced here, ahead of every pipeline and not as a filter, because an
    unset filter permits -- the 0.3.2 shape. Nothing binds a session to a
    principal: the 2026-07-28 revision has no session, and every state the
    proxy keeps across a person's requests is keyed on the principal."""
    from fastmcp.server.dependencies import get_access_token

    lifespan_context = ctx.lifespan_context
    mapping: PrincipalMapping | None = lifespan_context.get("principal_mapping")
    principal = principal_from_token(get_access_token(), mapping)
    if principal is None and lifespan_context.get("require_principal"):
        raise PrincipalError(
            "this proxy requires an authenticated principal and the request "
            "carries none"
        )
    return principal


def _admit_servers(router: BundleRouter, servers):
    """Run stage-one selection over the static servers, returning those the
    router admits. A refused server is logged and not connected.

    Logs the admission audit as it goes: one line per server naming the
    route, the deciding layer and the composed chain, and a closing count.
    A refused server is a warning. The point is that a gate which went
    missing shows up here as a server admitted to no chain, or a count that
    is one short, rather than as calls that simply succeed."""
    admitted = []
    for s in servers:
        decision = router.admit(
            server_name=s.name,
            url=s.url,
            how_loaded="static",
            transport="http" if s.url else "stdio",
        )
        record = router.admissions()[-1]
        if decision.allowed:
            logger.info("Admission: %s", record.summary())
            admitted.append(s)
        else:
            logger.warning("Admission: %s", record.summary())
    logger.info(
        "Admission audit: %d configured, %d admitted, %d refused",
        len(servers), len(admitted), len(servers) - len(admitted),
    )
    return admitted


_STATIC_INSTRUCTIONS = (
    "This server is a proxy to other MCP tool servers, listing the tools "
    "you may use under their qualified names (e.g. 'github__create_issue'). "
    "Call a listed tool with arguments matching its schema. A tool whose "
    "schema names a credential parameter requires that credential on every "
    "call; a refused call returns the reason.\n\n"
    "Authentication errors:\n"
    "- If a call fails with an authentication/token error, ask the user to "
    "fix the credential configured for that server, then retry the same call.\n"
    "- Never ask the user to provide tokens, secrets or keys in the "
    "conversation. Credentials are managed in the proxy's configuration only."
)


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
    auth: Any | None = None,
    principal_mapping: PrincipalMapping | None = None,
    require_principal: bool | None = None,
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

    ``auth`` is FastMCP's ``AuthProvider``, passed straight through: FastMCP
    verifies the bearer on each HTTP request against it, and the handlers
    turn the verified claims into the :class:`~extensible_mcp.types.Principal`
    every pipeline carries. Absent, ``config.auth`` builds a ``JWTVerifier``
    (resource-server mode: issuer, audience, JWKS or one public key); absent
    both, there is no inbound auth and every principal is ``None``.
    ``principal_mapping`` says which claim holds the roles and how its values
    map; absent, ``config.principal`` does, and absent that, ``roles`` read
    verbatim.

    ``require_principal`` is the deployment-mode selector, not a safety flag.
    ``True`` refuses every request that carries no principal, ahead of every
    pipeline, and requires ``auth``. ``False`` is an operator saying "single
    tenant on purpose": a per-person proxy on loopback, where every principal
    is ``None``. ``None`` is unset, which is what the HTTP transport's gate
    keys on (it refuses to serve HTTP with no ``auth`` and the flag unset).
    State the proxy keeps across a person's requests -- the discovered-tools
    set -- is keyed on the principal, or on the process when there is none;
    the protocol's 2026-07-28 revision has no session to key on.

    ``config.filters.policy_bundles`` — bundles declared in the config file
    rather than wired in code — are loaded here, before the lifespan exists,
    so a bundle that cannot be loaded raises from this call with the
    engine's own message. Their call filters run ahead of ``extra_call_filters``
    and their augmenter ahead of ``extra_search_filters``: what the config
    declares is enforced before anything an embedder appends.
    """
    declared_call_filters, declared_search_filters = build_declared_bundle_filters(
        config
    )
    extra_call_filters = [*declared_call_filters, *extra_call_filters]
    extra_search_filters = [*declared_search_filters, *extra_search_filters]

    if auth is None and config.auth is not None:
        auth = build_auth_provider(config.auth)
    if require_principal and auth is None:
        raise ValueError(
            "require_principal=True needs an inbound verifier: pass auth=, or "
            "configure an 'auth' block. With neither, no request could ever "
            "carry a principal and every call would be refused."
        )
    if principal_mapping is None:
        principal_mapping = PrincipalMapping(
            roles_claim=config.principal.roles_claim,
            role_map=config.principal.role_map,
        )

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
            principal_mapping=principal_mapping,
            require_principal=require_principal,
        )
        remove_handler = _install_reload_handler(ctx, reload_config)
        try:
            yield ctx
        finally:
            remove_handler()
            logger.info("Shutting down, closing connections...")
            await ctx["client_manager"].close_all()

    static = config.exposure == "static"
    server = FastMCP(
        name="extensible-mcp",
        middleware=[StaticExposure()] if static else [],
        instructions=_STATIC_INSTRUCTIONS if static else (
            "This server is a proxy to other MCP tool servers. "
            "You do not have direct tool definitions — discover them on demand.\n\n"
            "Workflow:\n"
            "1. Use `search_tools` with a natural language query to find relevant tools.\n"
            "2. Use `call_tool` with the qualified name from search results "
            "(e.g. 'github__create_issue') and arguments matching the returned schema.\n"
            "3. You may only call tools you have previously discovered via search_tools.\n\n"
            "Dynamic servers:\n"
            "- Use `load_mcp_server` to connect to a new remote MCP server by URL.\n"
            "- If the server requires authentication, ask the user to add the "
            "server to the config file with a credential (a 'credentials' entry, "
            "or a line in the tokens file), since a credential is only ever "
            "presented to a URL named in the config.\n\n"
            "Authentication errors:\n"
            "- If a call_tool fails with an authentication/token error, ask the user "
            "to fix the credential configured for that server, then retry the "
            "same call.\n"
            "- Never ask the user to provide tokens, secrets or keys in the "
            "conversation. Credentials are managed in the proxy's configuration "
            "only."
        ),
        lifespan=configured_lifespan,
        auth=auth,
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
        try:
            principal = _current_principal(ctx)
        except PrincipalError as e:
            return f"Error: {e}"
        results = vs.search(query, top_k=top_k)
        results = pipeline.apply(results, query, principal=principal)
        # Registered against this session, so what one conversation surfaced
        # does not become callable by another.
        # Registered against the principal (or the process), so what one
        # person surfaced does not become callable by another.
        discovered_filter.register([r.tool.qualified_name for r in results], principal)
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
        try:
            content, is_error, _structured = await _dispatch_call(ctx, tool_name, arguments)
        except _Refused as e:
            return e.text

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
        # Runtime loading is a stdio capability: one person, one process, a
        # server they chose. On a shared HTTP proxy a loaded server would join
        # the namespace every principal searches, so servers are configured
        # there, by an operator, not loaded. Refused at the handler rather
        # than hidden from the catalogue, since a hidden tool is a suggestion.
        if _over_http():
            return (
                "Error: load_mcp_server is not available over HTTP. On a shared "
                "proxy, servers are configured by the operator, not loaded; ask "
                "the user to add the server to the config file."
            )
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

        try:
            principal = _current_principal(ctx)
        except PrincipalError as e:
            return f"Error: {e}"
        load_request = ServerLoadRequest(server_name=server_name, url=url, principal=principal)
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
            logger.info("Admission: %s", router.admissions()[-1].summary())
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
        # The CLI is what creates the on-disk bearer, so it is the right
        # place to say that there is now a better option.
        print(
            "Note: this wrote a long-lived bearer to the tokens file, which "
            "remains supported and will be removed in a later release. A "
            "'credentials' entry in the config lets the proxy acquire a "
            "short-lived token by an OAuth grant instead."
        )

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
    require_principal: bool | None = None
    run_kwargs: dict[str, Any] = {}
    if args.transport == "http":
        try:
            require_principal = check_http_deployment(
                config, allow_anonymous=args.allow_anonymous, host=args.host
            )
        except TransportError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        run_kwargs = {"transport": "http", "host": args.host, "port": args.port}
    elif args.allow_anonymous:
        print("error: --allow-anonymous is only meaningful with --transport http", file=sys.stderr)
        return 2
    # reload_config is what arms SIGHUP. The CLI supplies it -- and with it the
    # policy that "the config" means this file -- while the lifespan supplies
    # the machinery, since only it holds the live manager and index.
    server = create_server(
        config,
        reload_config=lambda: load_config(config_path),
        require_principal=require_principal,
    )
    try:
        pid_file = admin.write_pid_file(config_path)
    except admin.AdminError as e:
        # Two proxies on one config would race on the same downstreams, and
        # leave add-server signalling whichever wrote the file last.
        print(f"error: {e}", file=sys.stderr)
        return 1
    try:
        server.run(**run_kwargs)
    finally:
        admin.remove_pid_file(pid_file)
    return 0

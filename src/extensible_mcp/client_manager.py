# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
import mcp.types as mcp_types

from .types import ServerConfig, ToolRecord

logger = logging.getLogger(__name__)

# How long close() waits for a connection's owner task to unwind its
# transport before giving up on an orderly shutdown and cancelling it.
CLOSE_TIMEOUT_SECONDS = 10.0


def _read_tokens_file(path: Path) -> dict[str, str]:
    """Read server_name=token pairs from a tokens property file."""
    if not path.exists():
        return {}
    tokens: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        tokens[key.strip()] = value
    return tokens


class TokenExpiredError(Exception):
    """Raised when an HTTP call fails with 401/403, suggesting the token has expired."""

    def __init__(self, server_name: str, token_age_minutes: int) -> None:
        self.server_name = server_name
        self.token_age_minutes = token_age_minutes
        super().__init__(
            f"Authentication failed for server '{server_name}' "
            f"(token unchanged for {token_age_minutes} minutes)"
        )


class _Connection:
    """Manages a single downstream MCP server connection (stdio or URL)."""

    def __init__(
        self,
        config: ServerConfig,
        tokens_file: Path | None = None,
        *,
        tokens_allowed: bool = False,
    ) -> None:
        self.config = config
        # Whether this connection may present a bearer token. False unless an
        # operator configured this exact URL for this name -- see
        # ClientManager.connect_url.
        self._tokens_allowed = tokens_allowed
        self.session: ClientSession | None = None
        # The task that owns the transport's context managers; see connect().
        self._owner: asyncio.Task[None] | None = None
        self._closing: asyncio.Event | None = None
        self._tokens_file = tokens_file
        self._last_token_value: str | None = None
        self._token_set_at: float | None = None

    def set_tokens_file(self, tokens_file: Path | None) -> None:
        self._tokens_file = tokens_file
        self._last_token_value = None
        self._token_set_at = None

    @property
    def is_url(self) -> bool:
        return self.config.url is not None

    @property
    def token_age_minutes(self) -> int:
        if self._token_set_at is None:
            return 0
        return int((time.monotonic() - self._token_set_at) / 60)

    def _resolve_token(self) -> str | None:
        """Read the current token for this server from the tokens file.

        Tracks when the token value last changed for age reporting.
        """
        if not self._tokens_file:
            return None
        tokens = _read_tokens_file(self._tokens_file)
        value = tokens.get(self.config.name)
        if value is None:
            self._last_token_value = None
            self._token_set_at = None
            return None
        if value != self._last_token_value:
            self._last_token_value = value
            self._token_set_at = time.monotonic()
        return value

    def _make_http_client(self) -> httpx.AsyncClient | None:
        """Build an httpx client with auth headers if a token is available
        *and* this connection is allowed to present one.

        A token is keyed by server name, but the URL it gets sent to is
        chosen by whoever opened the connection -- and for a runtime
        ``load_mcp_server`` that is the LLM. Sending a stored bearer token to
        an arbitrary model-supplied host would hand the credential to whoever
        the model was talked into naming, so credentials go only to a URL an
        operator configured.
        """
        if not self._tokens_allowed:
            if self._tokens_file and _read_tokens_file(self._tokens_file).get(
                self.config.name
            ):
                logger.warning(
                    "Not sending the stored token for %r to %s: credentials are "
                    "only presented to a URL configured for that name in the "
                    "config file, and this URL was supplied at runtime.",
                    self.config.name,
                    self.config.url,
                )
            return None
        token = self._resolve_token()
        if not token:
            return None
        return httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}"},
        )

    def _check_auth_error(self, exc: BaseException) -> None:
        """Raise TokenExpiredError if the exception looks like a 401/403."""
        if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code in (401, 403):
            raise TokenExpiredError(self.config.name, self.token_age_minutes) from exc
        msg = str(exc).lower()
        if "401" in msg or "403" in msg or "unauthorized" in msg or "forbidden" in msg:
            raise TokenExpiredError(self.config.name, self.token_age_minutes) from exc
        # anyio TaskGroups wrap downstream errors in an ExceptionGroup; recurse.
        if isinstance(exc, BaseExceptionGroup):
            for sub in exc.exceptions:
                self._check_auth_error(sub)

    async def connect(self) -> None:
        """Open a persistent connection. Used for stdio servers.

        The transport's context managers open anyio cancel scopes, and anyio
        requires the task that entered a scope to be the one that exits it.
        The first connect happens in the lifespan task, but a reconnect after
        a failed call happens in whichever request task made that call -- so
        the stack cannot simply live in the frame of whoever called connect.

        Instead each connection gets its own task, which enters the stack,
        parks until close() asks it to stop, and then unwinds in the same
        task that entered. connect() and close() are therefore safe to call
        from anywhere; both just hand instructions to that task and wait.
        The session itself is transport-agnostic (memory object streams), so
        calls still run directly in the request task.
        """
        if self._owner is not None:
            raise RuntimeError(f"Server '{self.config.name}' is already connected")
        loop = asyncio.get_running_loop()
        started: asyncio.Future[None] = loop.create_future()
        self._closing = asyncio.Event()
        self._owner = loop.create_task(self._own_transport(started))
        try:
            await started
        except BaseException:
            self._owner = None
            self._closing = None
            raise

    async def _own_transport(self, started: asyncio.Future[None]) -> None:
        """Hold the transport open for the life of the connection.

        Runs as its own task so that every enter/exit of the transport's
        cancel scopes happens here, whatever task called connect() or
        close().
        """
        closing = self._closing
        assert closing is not None
        try:
            async with AsyncExitStack() as stack:
                if self.config.url:
                    http_client = self._make_http_client()
                    if http_client:
                        await stack.enter_async_context(http_client)
                    read, write, _ = await stack.enter_async_context(
                        streamable_http_client(
                            self.config.url, http_client=http_client
                        )
                    )
                else:
                    params = StdioServerParameters(
                        command=self.config.command,
                        args=self.config.args,
                        env=self.config.env,
                    )
                    read, write = await stack.enter_async_context(stdio_client(params))
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()
                self.session = session
                started.set_result(None)
                await closing.wait()
        except asyncio.CancelledError:
            # Cancelled part-way through the transport's teardown, which for
            # stdio means the child was never signalled. Nothing to be done
            # about it here, but it must not look like a clean exit.
            if not started.done():
                started.cancel()
            logger.warning(
                "Transport for '%s' was cancelled before it finished closing",
                self.config.name,
            )
            raise
        except BaseException as exc:
            if not started.done():
                started.set_exception(exc)
            else:
                logger.warning(
                    "Transport for '%s' failed while closing",
                    self.config.name,
                    exc_info=True,
                )
        finally:
            self.session = None

    async def list_tools_ephemeral(self) -> list[mcp_types.Tool]:
        """Connect, list tools, and disconnect. Used for URL servers to avoid
        background tasks interfering with the stdio transport."""
        async with AsyncExitStack() as stack:
            http_client = self._make_http_client()
            if http_client:
                await stack.enter_async_context(http_client)
            read, write, _ = await stack.enter_async_context(
                streamable_http_client(self.config.url, http_client=http_client)
            )
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            result = await session.list_tools()
            return result.tools

    async def call_tool_ephemeral(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> mcp_types.CallToolResult:
        """Connect, call a tool, and disconnect. Used for URL servers."""
        try:
            async with AsyncExitStack() as stack:
                http_client = self._make_http_client()
                if http_client:
                    await stack.enter_async_context(http_client)
                read, write, _ = await stack.enter_async_context(
                    streamable_http_client(self.config.url, http_client=http_client)
                )
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()
                return await session.call_tool(tool_name, arguments)
        except TokenExpiredError:
            raise
        except Exception as exc:
            if self._last_token_value:
                self._check_auth_error(exc)
            raise

    async def close(self) -> None:
        """Ask the owner task to unwind the transport, and wait for it."""
        owner, self._owner = self._owner, None
        closing, self._closing = self._closing, None
        if owner is None:
            self.session = None
            return
        if closing is not None:
            closing.set()
        try:
            # Shielded: a stdio teardown cancelled half-way leaves the child
            # process running, so the owner is allowed to finish unwinding
            # even when whoever called close() is itself being cancelled.
            await asyncio.wait_for(asyncio.shield(owner), CLOSE_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            # A downstream that will not exit must not hold up the rest of
            # shutdown; past the deadline, stop waiting and cut it loose.
            logger.warning("Timed out closing connection to '%s'", self.config.name)
            owner.cancel()
        except Exception:
            logger.warning(
                "Error closing connection to '%s'", self.config.name, exc_info=True
            )
        finally:
            self.session = None


class ClientManager:
    def __init__(self, tokens_file: Path | None = None) -> None:
        self._connections: dict[str, _Connection] = {}
        self._tool_to_server: dict[str, str] = {}  # qualified_name -> server_name
        self._tool_original_name: dict[str, str] = {}  # qualified_name -> original name
        self._configured_urls: dict[str, str] = {}  # name -> URL from the config file
        self._tokens_file = tokens_file
        # Serializes connect_url: the name check and the registration are
        # separated by a network round-trip, so two concurrent loads of the
        # same name both passed the check.
        self._connect_lock = asyncio.Lock()

    async def connect_configured(self, config: ServerConfig) -> list[ToolRecord]:
        """Connect one server an *operator* configured, and index its tools.

        The counterpart to ``connect_url``, which serves the LLM: a server that
        arrives here was named in the config file, so it is allowed to present
        a stored credential. Recording it in ``_configured_urls`` is what
        authorizes that, and is why a reload must come through here rather than
        through ``connect_url``.

        Raises on failure; callers decide whether one bad server is fatal.
        """
        if config.url:
            self._configured_urls[config.name] = config.url
        conn = _Connection(config, tokens_file=self._tokens_file, tokens_allowed=True)
        if conn.is_url:
            tools_raw = await conn.list_tools_ephemeral()
            self._connections[config.name] = conn
            tools = self._index_tools(config.name, tools_raw)
        else:
            await conn.connect()
            self._connections[config.name] = conn
            result = await conn.session.list_tools()
            tools = self._index_tools(config.name, result.tools)
        logger.info("Connected to '%s': %d tools", config.name, len(tools))
        return tools

    async def connect_all(self, configs: list[ServerConfig]) -> list[ToolRecord]:
        all_tools: list[ToolRecord] = []
        for config in configs:
            try:
                all_tools.extend(await self.connect_configured(config))
            except Exception:
                logger.warning(
                    "Failed to connect to '%s', skipping", config.name, exc_info=True
                )
        if not self._connections:
            raise RuntimeError("Could not connect to any downstream MCP server")
        return all_tools

    def server_names(self) -> set[str]:
        """Names of the servers currently connected."""
        return set(self._connections)

    def set_tokens_file(self, tokens_file: Path | None) -> None:
        """Point at a (possibly new) tokens file.

        Needed because the file often does not exist when the proxy starts --
        ``load_config`` reports ``None`` for a tokens file that is not there --
        and the whole point of ``add-server`` is to create it afterwards. A
        reload that kept the startup value would connect the new server with no
        credential at all.

        Existing connections pick it up for free: a URL connection resolves the
        token per call.
        """
        if tokens_file == self._tokens_file:
            return
        logger.info("Tokens file is now: %s", tokens_file or "(none)")
        self._tokens_file = tokens_file
        for conn in self._connections.values():
            conn.set_tokens_file(tokens_file)

    def _index_tools(
        self, server_name: str, tools: list[mcp_types.Tool]
    ) -> list[ToolRecord]:
        records: list[ToolRecord] = []
        for tool in tools:
            qualified = f"{server_name}__{tool.name}"
            self._tool_to_server[qualified] = server_name
            self._tool_original_name[qualified] = tool.name
            records.append(
                ToolRecord(
                    name=tool.name,
                    qualified_name=qualified,
                    description=tool.description or "",
                    input_schema=tool.inputSchema,
                    server_name=server_name,
                )
            )
        return records

    async def call_tool(
        self, qualified_name: str, arguments: dict[str, Any]
    ) -> mcp_types.CallToolResult:
        server_name = self._tool_to_server.get(qualified_name)
        if not server_name:
            raise ValueError(f"Unknown tool: {qualified_name}")

        conn = self._connections.get(server_name)
        if not conn:
            raise RuntimeError(f"Server '{server_name}' is not connected")

        original_name = self._tool_original_name[qualified_name]

        if conn.is_url:
            return await conn.call_tool_ephemeral(original_name, arguments)

        if not conn.session:
            raise RuntimeError(f"Server '{server_name}' is not connected")

        try:
            return await conn.session.call_tool(original_name, arguments)
        except Exception:
            # Reconnect once and retry
            logger.warning(
                "Call to '%s' failed, attempting reconnect", qualified_name, exc_info=True
            )
            try:
                await conn.close()
                await conn.connect()
                result = await conn.session.list_tools()
                self._index_tools(server_name, result.tools)
                return await conn.session.call_tool(original_name, arguments)
            except Exception:
                logger.error(
                    "Reconnect to '%s' failed", server_name, exc_info=True
                )
                raise

    async def connect_url(self, name: str, url: str) -> list[ToolRecord]:
        """Connect to a remote MCP server by URL and index its tools."""
        async with self._connect_lock:
            return await self._connect_url_locked(name, url)

    async def _connect_url_locked(self, name: str, url: str) -> list[ToolRecord]:
        if name in self._connections:
            raise ValueError(f"Server '{name}' is already connected")
        config = ServerConfig(name=name, url=url)
        # The name and URL both come from the caller -- the LLM, via
        # load_mcp_server. Credentials are presented only when an operator
        # already named this exact URL in the config file.
        conn = _Connection(
            config,
            tokens_file=self._tokens_file,
            tokens_allowed=self._configured_urls.get(name) == url,
        )
        tools_raw = await conn.list_tools_ephemeral()
        self._connections[name] = conn
        tools = self._index_tools(name, tools_raw)
        logger.info("Connected to '%s' (%s): %d tools", name, url, len(tools))
        return tools

    def get_qualified_names(self) -> set[str]:
        return set(self._tool_to_server.keys())

    async def close_all(self) -> None:
        for conn in self._connections.values():
            await conn.close()
        self._connections.clear()

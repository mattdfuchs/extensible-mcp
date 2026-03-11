from __future__ import annotations

import logging
from contextlib import AsyncExitStack
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client
import mcp.types as mcp_types

from .types import ServerConfig, ToolRecord

logger = logging.getLogger(__name__)


class _Connection:
    """Manages a single downstream MCP server connection (stdio or URL)."""

    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self.session: ClientSession | None = None
        self._stack: AsyncExitStack | None = None

    async def connect(self) -> None:
        stack = AsyncExitStack()
        await stack.__aenter__()
        try:
            if self.config.url:
                read, write, _ = await stack.enter_async_context(
                    streamablehttp_client(self.config.url)
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
        except Exception:
            await stack.aclose()
            raise
        self._stack = stack
        self.session = session

    async def close(self) -> None:
        if self._stack:
            try:
                await self._stack.aclose()
            except Exception:
                pass
            self._stack = None
        self.session = None


class ClientManager:
    def __init__(self) -> None:
        self._connections: dict[str, _Connection] = {}
        self._tool_to_server: dict[str, str] = {}  # qualified_name -> server_name
        self._tool_original_name: dict[str, str] = {}  # qualified_name -> original name

    async def connect_all(self, configs: list[ServerConfig]) -> list[ToolRecord]:
        all_tools: list[ToolRecord] = []
        for config in configs:
            try:
                conn = _Connection(config)
                await conn.connect()
                self._connections[config.name] = conn
                tools = await self._index_server(config.name, conn.session)
                all_tools.extend(tools)
                logger.info(
                    "Connected to '%s': %d tools", config.name, len(tools)
                )
            except Exception:
                logger.warning(
                    "Failed to connect to '%s', skipping", config.name, exc_info=True
                )
        if not self._connections:
            raise RuntimeError("Could not connect to any downstream MCP server")
        return all_tools

    async def _index_server(
        self, server_name: str, session: ClientSession
    ) -> list[ToolRecord]:
        result = await session.list_tools()
        records: list[ToolRecord] = []
        for tool in result.tools:
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
        if not conn or not conn.session:
            raise RuntimeError(f"Server '{server_name}' is not connected")

        original_name = self._tool_original_name[qualified_name]

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
                await self._index_server(server_name, conn.session)
                return await conn.session.call_tool(original_name, arguments)
            except Exception:
                logger.error(
                    "Reconnect to '%s' failed", server_name, exc_info=True
                )
                raise

    async def connect_url(self, name: str, url: str) -> list[ToolRecord]:
        """Connect to a remote MCP server by URL and index its tools."""
        if name in self._connections:
            raise ValueError(f"Server '{name}' is already connected")
        config = ServerConfig(name=name, url=url)
        conn = _Connection(config)
        await conn.connect()
        self._connections[name] = conn
        tools = await self._index_server(name, conn.session)
        logger.info("Connected to '%s' (%s): %d tools", name, url, len(tools))
        return tools

    def get_qualified_names(self) -> set[str]:
        return set(self._tool_to_server.keys())

    async def close_all(self) -> None:
        for conn in self._connections.values():
            await conn.close()
        self._connections.clear()

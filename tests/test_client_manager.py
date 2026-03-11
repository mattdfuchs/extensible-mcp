import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from extensible_mcp.client_manager import ClientManager
from extensible_mcp.types import ServerConfig


MOCK_SERVER_PATH = str(Path(__file__).parent / "mock_server.py")


class TestClientManager:
    @pytest.mark.asyncio
    async def test_connect_and_index(self):
        """Connect to the mock server and verify tools are indexed."""
        mgr = ClientManager()
        configs = [
            ServerConfig(
                name="mock",
                command=sys.executable,
                args=[MOCK_SERVER_PATH],
            )
        ]
        try:
            tools = await mgr.connect_all(configs)
            assert len(tools) == 4
            names = {t.qualified_name for t in tools}
            assert "mock__add_numbers" in names
            assert "mock__send_email" in names
            assert "mock__search_files" in names
            assert "mock__delete_files" in names
        finally:
            await mgr.close_all()

    @pytest.mark.asyncio
    async def test_call_tool(self):
        """Call a tool on the mock server and verify the result."""
        mgr = ClientManager()
        configs = [
            ServerConfig(
                name="mock",
                command=sys.executable,
                args=[MOCK_SERVER_PATH],
            )
        ]
        try:
            await mgr.connect_all(configs)
            result = await mgr.call_tool("mock__add_numbers", {"a": 2, "b": 3})
            assert not result.isError
            text = result.content[0].text
            assert "5" in text
        finally:
            await mgr.close_all()

    @pytest.mark.asyncio
    async def test_call_unknown_tool(self):
        """Calling an unknown tool raises ValueError."""
        mgr = ClientManager()
        with pytest.raises(ValueError, match="Unknown tool"):
            await mgr.call_tool("nonexistent__tool", {})

    @pytest.mark.asyncio
    async def test_partial_startup(self):
        """One failing server doesn't prevent others from connecting."""
        mgr = ClientManager()
        configs = [
            ServerConfig(name="bad", command="/nonexistent/binary", args=[]),
            ServerConfig(
                name="mock",
                command=sys.executable,
                args=[MOCK_SERVER_PATH],
            ),
        ]
        try:
            tools = await mgr.connect_all(configs)
            assert len(tools) == 4  # only mock server's tools
            assert "mock__add_numbers" in mgr.get_qualified_names()
        finally:
            await mgr.close_all()

    @pytest.mark.asyncio
    async def test_all_servers_fail(self):
        """If all servers fail, connect_all raises RuntimeError."""
        mgr = ClientManager()
        configs = [
            ServerConfig(name="bad1", command="/nonexistent1", args=[]),
            ServerConfig(name="bad2", command="/nonexistent2", args=[]),
        ]
        with pytest.raises(RuntimeError, match="Could not connect"):
            await mgr.connect_all(configs)
